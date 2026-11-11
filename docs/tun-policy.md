# TUN policy integration

Lanrith builds the ordered access program into nftables. The TUN helper publishes
fresh device bindings, classification history and expiring directory grants into
that program's fixed sets. Stock TAYGA owns packet translation and dynamic source
allocation; Linux conntrack and source NAT handle connection state and egress.

NAT64 checks requests and replies in IPv6 on the client-facing side of its TUN
interface. NAT46 checks them in IPv4. The other side admits only the configured
translator's transit traffic. Enabling a translator grants no client access.
Physical source validation, protected destinations and managed-device identity
checks still precede owner permission.

The image finalizer runs `router-policy-profile -backend tun` against the compiled
baseline, numeric nftables listing and physical guard program. It installs the
resulting pinned profile and removes the intermediate inputs. The deployed helper
receives strict JSON, immutable program hashes and fixed executable paths. It does
not read owner YAML or compile an access program at startup.

Set publication preserves the directory and ownership evidence deadlines. A grant
belongs to the same association/address ownership episode that produced it. A
replacement binding cannot inherit the previous owner's grant. Revocation and
shutdown clear permission and delete labelled connections; an unrelated connection
is outside that cleanup scope. Program drift prevents positive writes while still
allowing permission removal.

Startup restores deny-only history and waits for a fresh binding publication before
reporting readiness to systemd. An explicitly incomplete publication keeps access
closed and is retried. A missing, unsafe or corrupt store requires the existing
initialization or recovery operation; startup does not silently create one.

The published legacy profile format remains supported by this component for older
images. TUN selection does not initialize its allocation supervisor, attachment
observers or packet witnesses. The former experimental replacements are absent
from this release branch.

Unit, race and native packet tests qualify the component boundary. Complete-image
boot, credential provisioning, rollback and physical performance need separate
qualification against the exact image that will be installed.
