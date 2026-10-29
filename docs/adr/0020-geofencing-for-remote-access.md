# 20. Geofencing for remote access

- Status: Accepted (owner decisions 2026-10-29)
- Date: 2026-10-29

## Context

Remote users reach the system over WireGuard (ADR 0017). The owner wants "the ability for
geofencing to ensure that only allowed regions can access the system via wireguard when we have
remote users". Source geography is a weak signal (VPNs and proxies hide it), so it must only
ever narrow access.

## Decision

1. **Geography only removes access, never grants it.** A valid key and identity are still
   required. Geofencing is an extra deny layer.
2. **Edge allow-list.** The remote-access edge accepts handshakes only from an allow-list of
   countries.
3. **Per-user regions.** Each user's allowed regions are held in the identity provider, as an
   attribute or a group, and are synced like other identity data (ADR 0015, ADR 0018).
4. **Disallowed region means revoke and alert.** A handshake or login from a region the user
   isn't allowed revokes that session's credentials (ADR 0019 kill switch, scoped to the
   session) and raises an alert.
5. **Impossible travel.** Two uses of an identity from locations it couldn't travel between in
   the elapsed time raise an alert and step up to re-authentication.
6. **Local GeoIP database,** updated by pull (outbound only, ADR 0017). Lookups never call an
   external service.

## Scalability

The GeoIP database is a read-only file on each edge, with no shared state. Impossible-travel
needs each identity's last location in the shared store (ADR 0016).

## Assume breach

- Prevent: the edge allow-list and per-user regions.
- Detect: alerts for disallowed regions and impossible travel.
- Contain: session revocation.
- Recover: re-authentication, then an admin review of the identity's recent activity.

GeoIP can be wrong or evaded, which is why it never grants access.

## Consequences

- Travelling users need a region change through the identity provider, an approved
  just-in-time exception, before they travel.
- The GeoIP database's freshness is monitored, and a stale database raises an alert.
