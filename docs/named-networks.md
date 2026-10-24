# Named network contract

The optional `network_model` baseline field replaces the six fixed role names
with router-selected network names. Existing baselines keep their original
validation and Untrusted policy boundary. The directory attribute retains the
`vlan_role` field; in this model its value names a declared network.

The root-owned model contains:

- `schema_version: 1`.
- `managed_networks`: networks whose inherited permissions require delegated grants.
- `uplink_interface`: the actual WAN interface.
- `core_services`: generated DNS, NTP, authoritative DNS and metrics listener
  and client attachments. These
  fixed component paths contain no directory credentials or arbitrary ports.
- `core_egress`: generated DNS/NTP upstream dependencies. Kind fixes the
  transport and listener; source, destination family and post-NAT source
  addresses remain explicit. These paths carry no delegated capabilities.
- `uplink_nat`: generated IPv4 source allocations and exact static WAN addresses.
  This geometry grants no access and contains no runtime address discovery.
- `service_prefixes`: generated managed-service allocations. They identify
  sources that cannot arrive from WAN, including unused addresses in an active
  pool. They remain separate from delegation limits, which do not ban owner
  permissions.
- `nat46_prefix`: the generated private `/96` used to embed IPv4 client
  addresses. It is present only when NAT46 is enabled. Validation keeps it
  separate from LAN, managed-service, router and NAT64 allocations.
- `rules`: ordered action, authorization, source, destination, protocol, ports
  and optional address family. Endpoint groups are already expanded into
  interface, CIDR and source-MAC constraints.

A model can declare two networks or several networks on separate physical
interfaces. VLAN zero represents an untagged attachment. Binding validation
still requires the actual interface, VLAN, address ownership and current
association to agree with independently loaded root geometry. A directory
attribute cannot declare a new network or change the managed boundary. Explicit
`directory` rules can require a grant on other declared networks too. An
`inherit` rule between networks without identity policy stays a static permission.

The compiler intersects each proposed TCP/UDP initiation with the ordered
ceiling. Dual-stack policies retain reachable native pairs when translators
are disabled. Unreachable cross-family pairs create no grants; every reachable
pair still passes ordering and security checks. An earlier deny terminates the decision. A matching owner permission
does not become a delegated capability. Partial owner rules remain in the
router's static access program; `controller_initiators` is rejected alongside
`network_model`. This prevents a port-specific permission from becoming access
to an entire destination network.

Router, management and service protections and explicit delegation limits
remain independently enforced. Alias resolution checks both the original
packet representation and its logical destination. Logical-interface
constraints survive translation: an interface and address must match the same
packet representation. A translator interface cannot borrow the native target's
address, and a native attachment cannot borrow the translated address. Grants,
terminal denies and independent candidate rechecks use this pairing, including
callbacks. Address ownership, classification history,
expiry, quotas and candidate revalidation retain their existing checks.
NAT64 source pools and retained source mappings are separate from NAT46
mappings. A native IPv6 source can retain its IPv4 alias with NAT46 disabled.
Unknown, inactive, reassigned and chained aliases do not become native peers or
permissions. Alias anchors prevent a directory rule from transferring to a new
host after a mapping changes. Display names and comments do not belong in this
enforcement contract.

Named helpers refresh physical ownership independently of directory requests.
The helper rereads its authenticated binding source every ten seconds, saves
deny-only address history and replaces four fixed ownership sets under the
same writer fence as grant updates. Each tuple contains the actual interface,
MAC and native address. Its kernel timeout stays below the original producer
deadline and the helper's elapsed-age limit. Diagnostic snapshots and saved
classification cannot supply positive ownership evidence.

Early and late forwarding checks reject a classified source without current
ownership. Final egress checks require current ownership for a classified
destination MAC too. A new association or ownership episode revokes the old
directory grants before replacing evidence. Directory failure seals grants
without renewing or removing independently valid ownership; a binding-source,
clock or persistence failure clears both. Startup and shutdown clear positive
ownership. Shadow supervision has no firewall write callbacks.

Named enforcement also requires a durable ownership sequence. Explicit first
installation initializes `ownership-epoch.json` beside the existing policy
history. A changed binding episode or helper restart consumes a new value
under the store lock and fsyncs it before publication. Routine collection keeps
the current value. Missing, corrupt, unsafe or exhausted sequence state closes
enforcement; startup does not initialize or reset it. Existing installations
need an explicit migration that qualifies initialization and connection-state
retirement. The separate file leaves policy-history bytes unchanged.

The fixed ownership transaction carries this value into a timed mark set and
a per-family mark map. Their lifetime is clipped by the collection's original
deadline and elapsed age. Inspection checks both family entries against the
set, including matching timeouts; revocation empties both objects under the
writer fence. Reader IPC, diagnostic snapshots and persisted sequence numbers
alone cannot publish current ownership. A kernel probe stamps real IPv4 and
IPv6 connections, then confirms that changing the epoch rejects old replies.
The high 22 mark bits identify the ownership epoch; the low ten bits reserve
an ordered rule identity. Constant rule bits survive stamping and checking in
the retained kernel. The counter rejects exhaustion before those fields can
overlap or wrap.
The epoch probe does not grant forwarding permission. Complete router
admission still needs bootstrap paths and translation proofs.

Static configuration has a separate epoch, consumed at helper startup. Its
helper-local proof binds the immutable baseline without querying the directory
or binding producer. A typed writer replaces only its fixed configuration
objects under the same profile and generation fence. The supervisor checks that
fence before collecting bindings. Directory or binding failures leave this
configuration epoch available while withdrawing delegated grants and stale
physical evidence. Shutdown clears both epochs. Native probes verify that
configuration-based connections survive ownership revocation, and that changing
either epoch rejects its own old connections. The separate native owner
component below selects and rechecks these epochs; complete router integration
remains gated.

Both epoch transactions also publish a fixed mark-to-classid conversion map
and a mirrored netdev epoch set. The conversion key is the admitted connection
epoch; it cannot assign the latest epoch to an old connection. Inspection checks
the exact value, canonical class identifier and original source deadline across
both families. Revocation empties the conversion and egress objects too.
The kernel probe carries the checked epoch through packet priority, denies a
return after its physical epoch entry is removed, preserves the QoS mark byte
and restores the priority before a later egress hook. Fixed save/restore helpers
now preserve standard priorities 0–7 in three reserved packet-mark bits outside
the QoS byte, rule index and tag. The retained-kernel probe uses actual socket
priorities for both families and both epoch types. It rejects unsupported class
identifiers instead of truncating them. The native owner component uses these
helpers; complete runtime activation remains gated.

The native predicate builder now takes an owned, validated copy of the ordered
model. It preserves each source/destination conjunction, family, interface,
protocol and listener port. It rejects oversized expansions before allocating
their packet rules. Original source MACs are checked before routing; a reply's
actual target MAC can be checked at physical egress. The caller still has to
bind predicates to the admitted rule and epoch across routing and NAT.

A retained-kernel fixture compares each generated predicate's JSON graph with
the actual nftables listing, then sends IPv4 and IPv6 TCP/UDP packets through
forward and egress hooks. Exact hosts, CIDRs, wildcards and `/0` selectors pass;
changed addresses, interfaces, protocols, ports and the relevant MAC fail.
These predicates carry no permission verdict by themselves.

A separate build-only native owner component now uses the ordered predicates,
configuration and ownership epochs, and priority channel together. It evaluates
both forward hooks and rechecks the actual packet and epoch at physical egress.
Managed sources require current attachment/address/MAC ownership at both
forward guards; managed targets require it at physical egress. Owner permissions
retain these checks. Ordinary static flows use the configuration epoch
and do not depend on the binding producer. Correlated owner replies retain the
original rule and current epoch; a directory callback rule cannot revoke that
permission. Explicit first-matching denies still apply.

The compiler counts reachable address-family and endpoint products before
allocating packet rules. It retains incoming interface/MAC/address alternatives
as a unit. Identical physical tuple gates share a chain, while translated source
classes keep separate ordering. Scope sharing leaves the current epoch, source
identity, grant and final packet checks mandatory. The same fixed context and
rule limits still apply.

The connection keeps its original rule index. At confirmation, the packet mark
instead carries that rule's bounded ingress/MAC policy context. Physical egress
can then apply first-match ordering to the final header without treating a deny
for another ingress or MAC as a match. An original packet cannot acquire an
earlier directory-only permission through a changed listener. Correlated owner
replies retain their separate callback behavior. Expansions above 1,024 packet
contexts or 16,384 generated rules are rejected.

The native component now admits directory traffic only while an exact grant
remains current. Both forwarding hooks check the device attachment, addresses,
protocol and listener. Eight fixed physical sets mirror the granted tuple for
each family, protocol and initiation direction. They keep the original grant
lifetime. Directory tags use the admitted source epoch; owner tags never consult
these grants. A matching directory requirement without a grant remains terminal.
Physical egress rechecks the current grant, exact source identity, target
ownership and epoch before restoring packet priority.

The default helper layout does not activate this component. Its private
constructor rejects translation geometry. The complete physical floor, translator
projections and correlated errors still need integration before an image may
activate it. It accepts no runtime rule fragments
or arbitrary writer operation.

The native component carries source identity separately from its policy MAC
class. Both families bind the original epoch, ingress, MAC and individual IP,
then check the exact IP at physical egress. Changing the source after
confirmation to another currently owned address in the same permitted prefix
is denied, including two IPv4 or two IPv6 addresses on the same MAC. A new flow
from the second address still passes.
Unmanaged static sources keep their separate path.

Each family has an inverse map retaining the original client address, a timed
per-address liveness set and an inet binding mirror for checks before rewriting.
A raw IPv4 binding mirror also lets a translator compare embedded client bits
without treating an IPv6 payload as an IPv4 datatype. It contains the same
per-address ID and original deadline; it creates no grant. The fifteen
metadata objects have typed publication and
withdrawal under the same writer fence. Inventories are bounded to 4,096 MAC
identities and 4,096 individual addresses per family; zero identifies an
unmanaged source. This provides source geometry for later translation wiring;
it does not activate a translated path.

Inventory IDs last for the original collection epoch so an individual address
expiry cannot renumber another device. IP proofs retain their shorter address
deadlines. Publication rederives every metadata byte from the local immutable
ownership proof under the existing writer fence. Snapshots and matching byte
digests cannot replace that evidence. Physical checks mask the epoch bits,
validate the exact source tuple, recheck the epoch and restore packet priority.
The original QoS byte and ordered policy context stay intact.

The native transaction also appends both permanent physical classifiers. Its
typed validator independently reconstructs all physical grant and classifier
operations from validated logical inputs. Generic mutation APIs reject this
schema; the inspected layout must select the same native geometry. Sealing
flushes every leased mirror and preserves historical classifiers.

A new classifier withdraws both positive epochs before publication, including
when the newly classified MAC has no IP. The engine serializes requests and
binding supervision, consumes a fresh configuration sequence, publishes the
additive deny history, then activates the new configuration epoch. The next
ownership publication consumes another sequence. Unchanged history and directory
outages do not rotate these epochs. State-save failure cleanup preserves newly
observed classifiers even when the save failed before rename. A failed epoch
transition requires a fresh helper startup; cleanup cannot restore a cached
positive epoch. Translated source identities still need their own projections.

The native owner fixture inspects the complete generated graph and exercises
IPv4/IPv6 TCP/UDP, partial selectors, callbacks, mandatory floor drops, wrong
interfaces and physical identities, changed listeners after confirmation, and
old connection rejection after either epoch changes. It also checks static
flows with physical ownership withdrawn. This qualifies the native component,
including native directory grants, without qualifying a complete router image.

The directory fixture exercises IPv4/IPv6 TCP/UDP in both initiation directions,
wrong source identities and protocols, and terminal absence of a grant before a
broader owner permission. Test-only egress hooks delete each exact physical proof
after confirmation; counters require the original and reply to reach that point
before final denial. Separate expiry checks leave the logical lease and source
epoch current. Static owner permissions remain available through withdrawal.

The native component checks fixed core-service client paths before its directory
classification guards. Both forwarding hooks require the declared client
attachment and prefix, exact service address and listener, and a separate
correlated core connection kind. Physical egress checks the actual scope,
rejects lost tags and invalid source changes, then restores packet priority.
This path needs no current NAS ownership or directory grant. Its reserved
connection kind cannot equal an ownership/configuration epoch.

The core packet fixture restores historical classifiers with no positive
ownership, configuration or grant evidence. IPv4/IPv6 DNS and authoritative
DNS TCP/UDP, NTP UDP and metrics TCP still pass. Other ports, wrong attachments,
source/interface changes and lost tags fail. NTP checks include redirection to
the local server and its correlated reply with the originally requested
server source. Physical destination checks also protect router addresses.

A separate upstream fixture exercises DNS TCP/UDP, NTP UDP and NTP's exact
numeric DNS fallback through real IPv4 and IPv6 source NAT, plus IPv6 without
NAT. Both forwarding hooks pin the original service identity and dependency;
all-packet postrouting guards run immediately before and after source NAT.
Physical egress pins the generated post-NAT address, WAN and listener. Replies
require the correlated core connection kind and original service destination.
Wrong sources, interfaces, ports and lost tags fail, including mutations after
source NAT and between confirmation and source NAT. Namespace account/source
guards remain independently required.

The separate IPv4 uplink-NAT component partitions each attached source range
at every immutable policy boundary. Its packet context preserves the original
ingress, source-MAC class and source-CIDR class. The guard at postrouting priority
99 checks the raw source against that context and the current per-address
ownership proof. Priority 101 requires an actual source-NAT binding and an exact
generated WAN address before issuing a physical NAT kind. A null source-NAT
binding keeps the native reply only if its original raw scope still holds.
NAT chains alone cannot perform these checks because they run for the first
packet of a connection.

Physical NAT checks keep the admitted rule's destination, protocol and listener,
re-evaluate first-match ordering using the saved source class, and check the
original epoch. Directory traffic additionally needs a current ID grant keyed
by the original source epoch, per-address identity, peer and listener. These
four typed sets in each of inet and netdev come only from the logical grant and a helper-local
receipt for a successfully published ownership proof. Their timeouts cannot
outlive either original deadline. Matching observations cannot mint a receipt;
a changed episode requires revocation, and a shorter published source deadline
withdraws old ID grants atomically. Static unclassified owner paths require no
NAS proof or directory grant.

The uplink-NAT packet fixture exercises actual IPv4 masquerading and correlated
returns, same-MAC address identities, early host denies, a terminal directory
requirement before a broader owner permission, and null-binding replies. It
withdraws a current physical grant or source proof after confirmation and
checks denial at egress. Changed raw sources, wrong interfaces and altered wire
tuples are denied. The fixture also requires the original QoS byte and packet
priority to survive NAT. These checks do not activate the default helper or
qualify NAT64/NAT46 policy integration.

Dynamic WAN addressing is represented without inventing an address. The native
constructor rejects that dependency until a qualified live uplink-address
producer is integrated. The default helper remains unchanged. Translated and
error paths still need integration before activation.

The forwarded-packet boundary checks router and management addresses, bogons
and source attachment ranges at both forwarding hooks and physical egress.
Source attachment ranges include the configured routed and additional subnets.
WAN cannot supply LAN or managed-service sources. Physical rule expansion keeps
the original incoming interface, MAC class and address alternative together;
changing an address after confirmation cannot borrow an alternative on another
interface. Replies retain that pairing too. Exact source-NAT paths use their
raw-source checks and pinned wire addresses instead of testing the rewritten
source against its original LAN prefix.

Exact core-service paths precede closure of their namespace interfaces, so a
wide owner rule cannot expose another service port. An all-packet guard at
postrouting priority 200 requires a declared forwarding egress and an admitted
connection kind. Losing both the mark and saved priority fails there. Local
router output remains subject to its separate root firewall; the forwarding
guard preserves neighbor discovery and other local control traffic.

The physical-floor fixture tests original and reply address substitutions in
both families with TCP/UDP, router and wrong-network source changes, protected
destinations, loss of both metadata fields, unknown egress and unused service
addresses spoofed from WAN. New flows from an independently permitted address
still pass. A delegation ceiling does not revoke an owner permission, and core
DNS works without NAS evidence while an undeclared service port is denied.

This contract does not complete runtime integration. The router must still
enforce the ordered policy on every native and translated packet, including
terminal directory requirements, static owner paths, source guards and current
translation proofs. A successful compiler decision or guard fixture does not
qualify those combined paths or a signed private image.

`packaging/kernel-vm.py` runs the legacy and named guard packet fixtures in an
offline VM. Build its static test binary with:

```sh
CGO_ENABLED=0 go test -c -tags integration,kernel,translationkernel \
  -o /tmp/router-policy-kernel-tests ./internal/firewall
python3 packaging/kernel-vm.py \
  --base /path/to/reviewed-base.tar.gz \
  --base-sha256 REVIEWED_SHA256 \
  --test-binary /tmp/router-policy-kernel-tests \
  --work /tmp/new-policy-guard-vm
```

The default run uses two disposable VMs: the existing thirteen-fixture suite
and six ordered-owner, physical-grant, core-service, uplink-NAT and physical-floor
fixtures. Both retain the 360-second VM limit; writer
fences remain two seconds. Aggregate qualification requires every fixture once,
with no skipped or failed subtests. Its input manifest binds both initramfs
images, their shared binary/kernel/source inventory, and both console digests.
Focused selections remain single-VM component checks.

The VMs also exercise ownership refresh, revocation and expiry, native nftables
inspection, classification restore and the existing controller and TAYGA
callback fixtures. It has no disk or external
network. It records source, binary, kernel and
initramfs digests and requires the packet-header mutation checks to run without
skips. Image signing, persistent migration, upgrade and rollback remain separate
qualification steps.

NAT46 also has an immutable destination projection model. It adds a raw IPv4
alias only when the same declared endpoint covers that alias on the translator
or its IPv6 target on the target attachment. It retains rule order, family,
transport, listener and authorization, and skips inactive mappings. This model
does not install packet hooks or activate shared translated enforcement.

Generated NAT46 metadata chains now carry the original rule, epoch, source ID
and saved priority for TCP, UDP and ICMP echo in both directions. Each output
needs a matching two-second input snapshot, exact target, translator prefix and
attachment. The full snapshot includes all three metadata fields. The packet's
carried epoch must equal its connection epoch, including high bits. A positive
connection keeps its original epoch; a reply needs an established reply path.
A nonzero IPv4 identity still needs its original raw-address proof.

The exporter deletes each old map value before inserting the current snapshot:
the retained kernel's dynamic map update alone refreshes its timeout without
replacing its data. Exact graph inspection covers the generated collections
and packet statements. Tests cover all six mappings, missing or changed
metadata, tuple changes, proof expiry, high source IDs and epoch changes.

These chains return or drop and install no hooks. Their caller must independently
check ordered scope, current grants, source attachment and destination ownership,
then repeat the required checks at physical egress. The packet fixture uses an
independent synthetic grant caller and verifies that a tuple snapshot alone
cannot forward traffic. Echo carries owner permission only; it acquires no
TCP/UDP grant. Shared translator activation and correlated ICMP errors remain
gated.

Static NAT46 source geometry now gives each eligible unmanaged IPv4 address on
its original attachment an independent identity. The compiler excludes managed
sources, router addresses and bogons, and bounds the union to 8,191 identities
before allocating rows. Geometry supplies connectivity facts only. Its publication
requires both the original opaque geometry and the current owner configuration
from the same baseline.

After a validated tuple import, the translated packet receives that identity in
a separate metadata namespace. Physical egress checks its exact embedded IPv6
source and the current configuration epoch. Changing to another eligible source
after import fails; a fresh flow from that source uses its own identity. Inspection
derives every permanent binding from the compiler geometry and rejects missing,
added or reassigned rows. The static component remains independent of NAS source
proofs and directory grants.

The tuple transport consumes static IDs only when constructed with the original
compiler-owned geometry. It keeps them separate from NAS IDs, checks the exact
client on both return legs and requires the current configuration epoch. Static
return tests join this path to the immutable connection facts below, including
long UDP replies, source substitution and epoch changes. The synthetic caller
still supplies permission independently.

Managed IPv4 sources also have an exact raw-address mirror at physical egress.
The translated IPv6 source must match that client's current IPv4 identity and
individual deadline. Return IPv4 destinations use the same identity. Withdrawing
only the physical proof or changing to another live address denies the packet
after inet admission. Neither source path installs a hook or grants permission.
Ordered scope, target ownership and directory integration still need shared
runtime qualification before the native constructor can enable NAT46.

Translation connection facts now retain the original context, source identity,
authorization namespace and epoch in reserved conntrack label bits. A new,
unconfirmed connection may capture these facts once. Subsequent original packets
must match them; a confirmed connection without facts cannot acquire a later
identity. Reply restoration requires the established reply direction and the
original connection epoch. It preserves the current packet's QoS and priority.
The low 32 label bits remain available for a separate NAT64 allocation identity.

The fact chains supply no forwarding verdict. Their caller must check the
current scope, source proof and grant before capture and after reply restoration,
then check them again at physical egress. The kernel fixture uses an independent
synthetic caller to test withdrawal and replies after the short tuple expires.
It also rejects changed contexts, identities and authorization namespaces on an
existing connection. Shared translator activation remains gated.


NAT46 wire policy now projects the original IPv4 source selectors into the
translation prefix while retaining paired interfaces, targets, protocols and
listeners. It rechecks first-match ordering against the original rule and
context. A matching directory requirement needs the current typed IPv4 source
grant and cannot fall through to a later owner permit. Static source geometry
and managed device identities retain separate authorization namespaces.

The ordered-wire packet fixture joins these predicates, immutable connection
facts and the production grant projection. It checks owner TCP/UDP/echo replies,
terminal directory requirements, both grant mirrors, expiry, wrong interfaces
and changes after inet admission. Observed grants must fit the original logical
grant, ownership epoch and individual address lifetime; the stable ID inventory
cannot keep an expired address authorized. Exact kernel graph comparison covers
policy and grant chains. Independent synthetic callers still supply metadata;
shared translator hooks, target ownership and complete image qualification remain
pending.

An explicit empty `managed_networks` array supports configurations without
inherited directory policy. Missing or null values remain invalid. Explicit
`directory` rules on declared networks still require their own current grants.


Static NAT46 geometry now checks permanent classification history before
handoff, tuple transport and physical egress. The owned model adds each
classified IPv4 address's embedded IPv6 counterpart and each classified mapped
IPv6 target's alias to the runtime deny history. It leaves persisted history
unchanged. Projection cannot create a grant or a current ownership claim;
restoration retains the cohort anchor and fixed classifier capacities.

Packet tests add only classification history while configuration epochs,
current caller permission and fresh tuples remain live. Both original and
return paths deny classified clients and mapped targets. Physical-only history
checks retain early admission counters, proving that denial occurs at egress.

A separate mapped-target ownership fact now keeps the IPv6 device's original
individual deadline visible on the IPv4 return path. Its typed publisher and
inspector derive an epoch/address mirror from current ownership. Wire egress
also requires the target's actual interface, Ethernet destination and IPv6
address. Return IPv4 packets use their compiler-owned alias/target pairing.
Tests withdraw or expire only this mirror while the global epoch remains live;
both directions deny. Source-epoch namespaces consume this fact independently
of the client's identity. Configuration-epoch namespaces cannot borrow it.
The target fixture uses synthetic caller metadata; complete shared policy,
mixed-family directory grants and translator activation remain pending.


Mixed-family destination grants now have separate typed IPv4 and IPv6
projections. The publisher pairs a logical IPv4 alias grant with the original
owned IPv6 target, its interface and MAC, and the compiler-owned mapping. The
wire key uses the embedded client address; the raw key uses that client's IPv4
address. Both retain the original peer, listener and source epoch. Static client
GIDs cannot consume the IPv4 NAS identity grant namespace.

A typed preparation retains the original model, ownership receipt and clock
anchors. Validation reconstructs the complete transaction and checks the current
remaining ownership deadline. Sealing clears the eight fixed projections without
creating an authorization clock or positive lease. Generic mutation APIs reject
the component's collections. The explicitly selected publication mode now
revokes these projections on source changes; full translator activation remains
gated.

The mixed-grant packet fixture checks TCP/UDP across all four translator legs,
both table families, expiration, individual mirror withdrawal and packet changes
after inet admission. Exact inspection covers both tables' grant chains and
collection headers. Its metadata caller remains synthetic; it executes the
validated mixed-grant subset and qualifies no shared writer or forwarding floor.
The complete suite now uses four disposable VM batches with unchanged timeouts
and writer fences. Uplink-NAT inspection shares a batch with the translator
fixtures so it still checks their table cleanup.

Static IPv4 clients reaching a managed IPv6 target now have a separate source
epoch handoff. Original compiler geometry supplies the client GID; the original
ownership receipt supplies the epoch and its remaining deadline. A typed writer
rederives the channel and both physical liveness mirrors from those proofs.
Listings can reject inconsistent data but cannot renew authority. Revocation
clears only the three fixed collections and closes existing connections too.

The joined packet fixture checks source GIDs above 1,023, current target IPv6
ownership, ordered owner and directory rules, mixed destination grants,
immutable connection facts and fresh return tuples. Owner TCP/UDP/echo and
directory TCP/UDP pass; unsolicited callbacks, expired grants, withdrawn mirrors
and changed sources, listeners or metadata deny. Target classification requires
current ownership; client classification closes the static namespace. Exact
kernel inspection checks the packet graph and collection headers.

The original raw IPv4 decision remains synthetic in this fixture. These checks
do not qualify the shared forwarding floor, live translator, binding producer
or default helper activation.

Mapped contexts now retain the original root rule, ingress and MAC class,
selected ready mapping and protocol. They occupy separate bounded context IDs
after the native inventory. Original IPv4 classes needed only after NAT44 can
share a translated context because the full source address remains visible in
the embedded IPv6 address. Source UIDs and GIDs stay in their own namespaces.
Immutable literal lookups bind each context to its actual endpoint, interface
and protocol. Ordered scopes retain native destination prefixes and project
only the selected aliases, preserving their paired attachments.

The joined context fixture checks current ownership, grants, source identity,
connection facts and tuple proofs in both table families. Its original raw
policy decision remains synthetic. Fixtures use distinct connection tuples:
conntrack facts correctly survive deletion of their test links and cannot be
reassigned to a later fixture's context.

Native authorization kinds also share identical ingress selection predicates.
Each caller keeps its exact kind, rule and epoch checks before and after source
handoff. Identical native physical predicates can share a gate containing every
original context ID; rewritten IPv4 source classes remain separate. The compiler
checks that its rule count equals the generated program and retains the
16,384-rule capacity. The complete shared translator layout remains pending.

Rules with a source MAC selector now create classes only on their declared
incoming interfaces. Unscoped selectors still apply on every interface. This
removes duplicate contexts while retaining the same ordered predicates.

The translated transport can share eight paths for current epoch and source
validation. Each selected mapping, protocol and direction retains its own
geometry, tuple maps and updates. The shared validators cannot publish tuples
or accept traffic. Source handoffs can also share an original interface and
authorization kind, retaining every explicit context ID. Duplicate IDs, mixed
interfaces and invalid families fail construction; caller order cannot change
the group's identity. The joined kernel fixture verifies the selected program
and its current grant, ownership, classification and return checks.

Publication backend selection is qualified separately below. Complete forwarding-
floor integration remains pending. The default helper still excludes this
translator mode.


An explicitly selected NAT46 publication layout now supplies the guarded
backend's source channels and mixed destination grants. Source publication uses
the original compiler model and ownership receipt. Grant inspection intersects
the full logical permission with current target ownership, retaining the alias,
interface, MAC, peer, protocol, listener and shorter deadline. Listings can reject
inconsistent data; they cannot create a receipt or renew a grant.

Source revocation clears 42 fixed objects in this mode, including its source
channel and mixed grants. Ordinary native layouts still clear 31 objects.
Configuration publication combines its epoch and static conversion channel in
one transaction; its clear removes five fixed objects and retains source ownership. Directory
sealing removes grants while retaining independently current source and
configuration facts. Deny history is retained from both table families and
restored with its translated counterparts.

Grant preparation retains the original authorization and source time anchors
outside the writer critical section. Commit checks the current whole profile,
original cached receipt, epoch and cohort quota under a fresh fence. The executor
independently reconstructs the complete transaction before mutation. Readback
rechecks generation and the original receipt under another fence, and inspection
must pass before success is returned. A queued grant cannot adopt a refreshed receipt, even when
the numeric epoch is unchanged. Writer, command and preparation limits remain
two seconds; failure cleanup has four seconds overall for bounded revocation
and verification. None of these steps extends a lease.

Two kernel fixtures exercise the actual typed backend with synthetic binding
and directory observations. They cover startup, shorter individual lifetimes,
independent revocation, damaged grant content, deny history retained only in the physical table,
external floor changes, closed generations and restart recovery. The complete
30-fixture suite preserves the original 28 fixtures and uses four disposable
VM groups with the same per-VM and per-fixture limits.

Inspection validates the complete JSON once before exact object checks. Fixed
field encodings come only from the completed layout generated from trusted configuration. Cached
expectations contain no kernel observations or live lease data. Required keys,
null rejection, handles, expressions, rule ordering, types and dynamic proof
relationships remain checked. Differential tests compare the optimized tuple
decoder with the original strict decoder and compare cached with uncached field
acceptance.

These publication fixtures use a native skeleton with the selected data
collections. The complete raw and translated forwarding floor, live translator
and binding-producer integration, and private-image qualification remain
pending. The default helper still excludes translation activation.


An explicitly constructed NAT46 forwarding layout now connects the native
ordered policy and mandatory guards to a real translator. Its four packet legs
retain the original source attachment, mapping, protocol, authorization and
current endpoint ownership. Return packets require immutable connection facts
and a fresh full tuple. Return export runs after the independent root floor.
Owner permissions still require current source and target proofs. Directory
permissions retain the original listener, peer and individual deadline.

Three kernel fixtures use real TAYGA with six synthetic mappings. They exercise
static source identities, current NAS IPv4 identities and an unmanaged network
without directory publication. TCP handshakes, UDP and echo round trips pass;
missing grants, owner denies, a root-floor deny, spoofed identities, wrong
attachments, unmapped aliases and unsolicited callbacks remain closed. Existing
UDP replies continue after the forward tuple expires, using current ownership
and a fresh reverse tuple. Physical ownership withdrawal closes old replies.

The compiler shares repeated identity and leg checks after selecting exact
mapping geometry. It removes a mapped scope only when earlier terminal rules
cover its complete source-prefix and listener product. Partial coverage retains
the scope. Fixed literal-set comparison ignores kernel member order while
preserving complete rows, duplicates, expression order and concatenation fields.

This constructor remains separate from installed profile admission. Combined
NAT64, WAN and service-namespace targets, reverse source-MAC rules, live binding
production and private-image qualification remain pending. The default helper
still excludes translator activation.


The final native capacity check counts every rule in both compiled table
schemas, including fixed guard and hook rules. Incremental construction budgets
remain in place. The protected artifact retains its separate 8,192-object limit;
helper inventory comes from the exact completed code-owned schema. A larger
helper cannot lend that allowance to protected objects. Output remains bounded
to 16 MiB and inspection still checks every object and expression.

Within one original endpoint pair and address family, independent address and
listener alternatives can share a literal set. Interface and MAC alternatives
remain separate. Overlapping and adjacent prefixes retain their original
expansion. The original logical selector-product quota is unchanged. Direction
and state entry checks share one conjunction, and metadata stamping retains its
original order before the same final verdict.

Differential tests compare 110,592 packet combinations with the original
unfactored predicates. Kernel cases cover literal hosts, prefixes, second
alternatives and address/listener gaps across IPv4, IPv6, TCP, UDP, replies and
physical egress. Typed reverse echo fields constrain the protocol without a
redundant comparison that nftables removes. The complete existing kernel suite
and its timeout limits remain in place.
