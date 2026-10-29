# 17. Outbound only, never ingress, and an encrypted, key-identified control plane

- Status: Accepted (owner decisions 2026-10-29)
- Date: 2026-10-29
- Amends: ADR 0014

## Context

ADR 0014 made polling the default and left a webhook relay as a later option with an
exposure approval. The owner has tightened that into a rule: "always prefer and use outbound
calls never allowing for ingress as those will need to pass any CISO's office audits and
requirements". Control-plane traffic (build requests, approvals, reviews) also carries the
decisions the whole product rests on. It must never cross a network in plaintext, and peers
must be identified cryptographically, not by address.

## Decision

**Outbound only, never ingress.**

1. Every integration starts from inside the customer's network. AegisX9 polls the vendor API
   or pulls from an outbound-only relay or queue. There are no webhooks, no SCIM push and no
   inbound callbacks from vendors.
2. Inside the network, agents and hosts dial the control plane. The control plane never
   dials them.
3. Large organisations that hit vendor rate limits use an outbound-only relay. Events are
   queued outside, AegisX9 pulls them, and events are hints that are always re-read
   (ADR 0014).
4. This replaces ADR 0014's "webhook relay with an exposure approval" option: an inbound
   route is not offered.

**Encrypted, key-identified control plane.**

5. Control-plane traffic travels only over WireGuard or mutual TLS. It is never plaintext,
   not even on a trusted LAN.
6. Peers are identified by key (a WireGuard public key, or a client certificate), never by IP
   address. Unknown keys and failed handshakes fail closed.
7. The topology is designed for multiple hubs, with every spoke peered to every hub, and
   clients are configured with an ordered endpoint list and fail over in order. A single-hub
   deployment is allowed until HA is built (ADR 0016), but it uses the same list format.

**Acceptance checklist** (every component, every release): no inbound listener reachable from
outside the trust boundary; every control-plane connection is authenticated by key and
encrypted; a peer with an unknown key is refused. Once HA is built (ADR 0016): losing one hub
does not stop the control plane.

## Scalability

Hubs are stateless relays and scale by adding hubs; spokes hold an ordered list. Poll cursors
use server-side leases with fenced cursor updates and idempotent event handling (ADR 0016), so
a duplicate poll by a replica that outlived its lease has no effect. A relay is an
external queue with its own HA.

## Consequences

- A connector that needs an inbound webhook doesn't clear the trust bar (ADR 0014). It needs a
  relay or a polling mode.
- Loopback-only listeners (for example the developer login callback on 127.0.0.1) are inside
  the trust boundary and are allowed.
- Polling costs API quota and adds latency up to the poll interval. Conditional requests
  keep the cost down, and the gate re-checks state before it acts, so a late event is never
  unsafe.
