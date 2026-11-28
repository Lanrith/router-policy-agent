// Package directory collects original LDAP entries over explicit transports.
// It neither supplies network bindings nor authenticates a NAS session.
package directory

import (
	"context"
	"crypto/x509"
	"errors"
	"net"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-ldap/ldap/v3"
	"github.com/lanrith/router-policy-agent/internal/policy"
)

// ErrRead deliberately excludes directory diagnostics, credentials and entries.
var ErrRead = errors.New("directory: collection failed")

// Config is private deployment configuration, never a group attribute.
// URL normally requires verified ldaps:// or ldap+starttls://; PlaintextUntil
// is a bounded private test exception. RootCAs nil uses system roots for TLS.
// Deployment must separately qualify direct search and reserved-field controls.
type Config struct {
	URL            string
	BaseDN         string
	SearchMode     string
	Mapping        *Mapping
	RootCAs        *x509.CertPool
	Timeout        time.Duration
	PageSize       uint32
	MaximumDevices int
	MaximumGroups  int
	// PlaintextUntil explicitly permits a short private-literal-IP LDAP test.
	// Zero requires verified LDAPS. It is never a TLS-failure fallback.
	PlaintextUntil time.Time
}

// Credentials are obtained again for every collection to support rotation.
// No serializer should expose the secret or the private lookup identity.
type Credentials struct {
	BindDN   string `json:"-"`
	Password string `json:"-"`
}

type pageRequirement uint8

const (
	ordinaryRead pageRequirement = iota
	onePopulatedPage
	multiplePopulatedPages
	ordinaryFixture
)

// Reader owns immutable connection configuration, but caches no directory data.
// Concurrent collections use separate bounded connections and snapshots.
type Reader struct {
	mapping     Mapping
	checkPages  pageRequirement
	config      Config
	address     string
	hostname    string
	credentials func(context.Context) (Credentials, error)
	now         func() time.Time
}

// New checks transport, namespace and quotas without connecting to a server.
// credentials must provide the separately authorized scoped read identity and
// honor cancellation. It must be safe for concurrent use if the Reader is shared.
func New(config Config, credentials func(context.Context) (Credentials, error)) (*Reader, error) {
	endpoint, err := url.Parse(config.URL)
	if err != nil || endpoint == nil {
		return nil, errors.New("directory: invalid endpoint")
	}
	isUnsafeEndpoint := endpoint.User != nil ||
		endpoint.Path != "" || endpoint.RawQuery != "" || endpoint.Fragment != "" ||
		endpoint.Opaque != "" || endpoint.ForceQuery
	host, port, splitErr := net.SplitHostPort(endpoint.Host)
	portNumber, portErr := strconv.ParseUint(port, 10, 16)
	if isUnsafeEndpoint || splitErr != nil || portErr != nil || portNumber == 0 || host == "" {
		return nil, errors.New("directory: verified ldaps endpoint required")
	}
	if !validTransport(config, endpoint.Scheme, host, time.Now().UTC()) {
		return nil, errors.New("directory: invalid or expired transport policy")
	}
	base, parseErr := ldap.ParseDN(config.BaseDN)
	isBadNamespace := parseErr != nil || base == nil || len(base.RDNs) == 0 || len(config.BaseDN) > 1024
	isBadTimeout := config.Timeout <= 0 || config.Timeout > 10*time.Second
	isBadCapacity := config.MaximumDevices <= 0 || config.MaximumDevices > 4096 ||
		config.MaximumGroups <= 0 || config.MaximumGroups > 8192
	isBadPaging := config.PageSize == 0 || config.PageSize > 256
	if credentials == nil || isBadNamespace || isBadTimeout || isBadCapacity || isBadPaging {
		return nil, errors.New("directory: invalid namespace, timing or collection limits")
	}
	switch config.SearchMode {
	case "", "auto":
		config.SearchMode = "auto"
	case "paged", "unpaged":
	default:
		return nil, errors.New("directory: unknown search mode")
	}
	mapping := defaultMapping(config.BaseDN)
	if config.Mapping != nil {
		mapping = *config.Mapping
		if !mapping.valid(base) {
			return nil, errors.New("directory: invalid LDAP mapping")
		}
		config.Mapping = &mapping
	}
	if config.RootCAs != nil {
		config.RootCAs = config.RootCAs.Clone()
	}
	return &Reader{
		config: config, mapping: mapping, address: endpoint.Host, hostname: host,
		credentials: credentials, now: time.Now,
	}, nil
}

func validTransport(config Config, scheme, host string, now time.Time) bool {
	if scheme == "ldaps" || scheme == "ldap+starttls" {
		return config.PlaintextUntil.IsZero()
	}
	address, err := netip.ParseAddr(host)
	validAddress := err == nil && !address.Is4In6() && address.Zone() == "" &&
		(address.IsPrivate() || address.IsLoopback())
	validDeadline := !now.IsZero() && now.Before(config.PlaintextUntil) &&
		config.PlaintextUntil.Sub(now) <= 24*time.Hour
	return scheme == "ldap" && validAddress && validDeadline && config.RootCAs == nil
}

type searcher interface {
	Search(*ldap.SearchRequest) (*ldap.SearchResult, error)
}

// CheckProvider reads a complete synthetic policy fixture over verified TLS.
// A one-entry page size must exercise a continuation with entries in both
// namespaces. The ordinary page size must complete both in one nonempty page.
func (r *Reader) CheckProvider(ctx context.Context, multiplePages bool) (policy.DirectorySnapshot, error) {
	if r == nil || !r.config.PlaintextUntil.IsZero() {
		return policy.DirectorySnapshot{}, ErrRead
	}
	check := *r
	check.config.SearchMode = "paged"
	check.checkPages = onePopulatedPage
	if multiplePages {
		check.checkPages = multiplePopulatedPages
		check.config.PageSize = 1
	}
	return check.Collect(ctx)
}

// CheckUnpaged qualifies a complete control-free search over verified TLS.
func (r *Reader) CheckUnpaged(ctx context.Context) (policy.DirectorySnapshot, error) {
	if r == nil || !r.config.PlaintextUntil.IsZero() {
		return policy.DirectorySnapshot{}, ErrRead
	}
	check := *r
	check.config.SearchMode = "unpaged"
	check.checkPages = ordinaryFixture
	snapshot, err := check.Collect(ctx)
	if err != nil {
		return policy.DirectorySnapshot{}, err
	}
	if !slices.ContainsFunc(snapshot.Devices, func(device policy.Device) bool { return device.Active && len(device.GroupIDs) > 0 }) {
		return policy.DirectorySnapshot{}, ErrRead
	}
	return snapshot, nil
}

// Collect returns a complete bounded snapshot or no snapshot at all.
// Its authorization age starts before dialing and includes every read.
// Certificate/hostname failure never falls back to plaintext or another host.
// An explicit plaintext test is deadline-bounded and rechecked before return.
func (r *Reader) Collect(ctx context.Context) (result policy.DirectorySnapshot, resultErr error) {
	if r == nil || r.credentials == nil || r.now == nil || ctx == nil {
		return policy.DirectorySnapshot{}, ErrRead
	}
	ctx, cancel := context.WithTimeout(ctx, r.config.Timeout)
	defer cancel()
	observed := r.now().UTC()
	isPlaintext := !r.config.PlaintextUntil.IsZero()
	if isPlaintext {
		if !observed.Before(r.config.PlaintextUntil) {
			return policy.DirectorySnapshot{}, ErrRead
		}
		var cancelException context.CancelFunc
		ctx, cancelException = context.WithDeadline(ctx, r.config.PlaintextUntil)
		defer cancelException()
	}
	credentials, err := r.credentials(ctx)
	if err != nil || ctx.Err() != nil || !validCredentials(credentials, r.config.BaseDN, r.config.Mapping != nil) {
		return policy.DirectorySnapshot{}, readError(ctx)
	}
	connection, err := r.dial(ctx, isPlaintext)
	if err != nil {
		return policy.DirectorySnapshot{}, readError(ctx)
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		if closeErr := connection.Close(); closeErr != nil {
			return policy.DirectorySnapshot{}, ErrRead
		}
		return policy.DirectorySnapshot{}, ErrRead
	}
	if err := connection.SetDeadline(deadline); err != nil {
		if closeErr := connection.Close(); closeErr != nil {
			return policy.DirectorySnapshot{}, ErrRead
		}
		return policy.DirectorySnapshot{}, ErrRead
	}
	bounded := &boundedConn{
		Conn: connection, reader: newFrameReader(connection),
	}
	client := ldap.NewConn(bounded, !isPlaintext)
	client.SetTimeout(r.config.Timeout)
	client.Start()
	closed := make(chan struct{})
	stop := context.AfterFunc(ctx, func() {
		// Close records the redacted failure for the joined cleanup below.
		_ = bounded.Close()
		close(closed)
	})
	defer func() {
		if !stop() {
			<-closed
		}
		// Close the socket first so blocked library I/O cannot delay joining.
		socketErr := bounded.Close()
		libraryErr := client.Close()
		if unexpectedClose(socketErr) || unexpectedClose(libraryErr) {
			result, resultErr = policy.DirectorySnapshot{}, readError(ctx)
		}
	}()
	if err := safeBind(client, credentials); err != nil {
		return policy.DirectorySnapshot{}, readError(ctx)
	}
	snapshot, err := r.collect(ctx, client, observed)
	if err != nil || ctx.Err() != nil || isPlaintext && !r.now().UTC().Before(r.config.PlaintextUntil) {
		return policy.DirectorySnapshot{}, readError(ctx)
	}
	return snapshot, nil
}

func (r *Reader) dial(ctx context.Context, isPlaintext bool) (net.Conn, error) {
	network := &net.Dialer{Timeout: r.config.Timeout}
	if isPlaintext {
		return network.DialContext(ctx, "tcp", r.address)
	}
	return r.dialVerified(ctx)
}

// safeBind confines the dependency's response-shape assumptions to the
// untrusted LDAP boundary. A malformed server packet cannot crash the reader.
func safeBind(client *ldap.Conn, credentials Credentials) (resultErr error) {
	defer func() {
		if recover() != nil {
			resultErr = ErrRead
		}
	}()
	return client.Bind(credentials.BindDN, credentials.Password)
}

func safeSearch(client searcher, request *ldap.SearchRequest) (result *ldap.SearchResult, resultErr error) {
	defer func() {
		if recover() != nil {
			result, resultErr = nil, ErrRead
		}
	}()
	return client.Search(request)
}

func validCredentials(credentials Credentials, baseDN string, mapped bool) bool {
	if credentials.Password == "" || len(credentials.Password) > 4096 || credentials.BindDN == "" || len(credentials.BindDN) > 2048 || strings.IndexByte(credentials.BindDN, 0) >= 0 {
		return false
	}
	dn, err := ldap.ParseDN(credentials.BindDN)
	if mapped {
		base, baseErr := ldap.ParseDN(baseDN)
		return err == nil && baseErr == nil && dn != nil && base != nil && base.AncestorOf(dn)
	}
	base, baseErr := ldap.ParseDN("ou=users," + baseDN)
	return err == nil && baseErr == nil && dn != nil && base != nil &&
		len(dn.RDNs) == len(base.RDNs)+1 && base.AncestorOfFold(dn)
}

func readError(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return errors.Join(ErrRead, err)
	}
	return ErrRead
}

// boundedConn closes the transport once even when cancellation and LDAP cleanup
// race. Its reader checks framing budgets before the library allocates a tree.
type boundedConn struct {
	net.Conn
	reader   *frameReader
	closeOne sync.Once
	closeErr error
}

func (c *boundedConn) Read(data []byte) (int, error) { return c.reader.Read(data) }

func (c *boundedConn) Close() error {
	c.closeOne.Do(func() { c.closeErr = c.Conn.Close() })
	return c.closeErr
}

func unexpectedClose(err error) bool { return err != nil && !errors.Is(err, net.ErrClosed) }

func (r *Reader) canonicalDN(raw string) (string, error) {
	if raw == "" || len(raw) > 2048 || strings.ContainsRune(raw, '\x00') {
		return "", ErrRead
	}
	dn, err := ldap.ParseDN(raw)
	if err != nil || dn == nil || len(dn.RDNs) == 0 {
		return "", ErrRead
	}
	if r.config.Mapping != nil {
		return dn.String(), nil
	}
	return strings.ToLower(dn.String()), nil
}
