# TLS mode 1 verification ownership

This change fixes a connection-ownership deadlock. It does not turn self-signed TLS mode 1 into a trusted identity protocol or fix all transport/lifecycle issues.

## Negotiation and ownership

The client offers `X-Tunveo-Verification: flow-v1` in the existing authenticated HTTPS handshake. The server returns an additional JSON `verify` field:

- `flow-v1` only when that exact capability was offered;
- `legacy` otherwise. An old server may omit the field, which the new client treats as legacy.

Unknown response values are rejected. Do not strip or inject the negotiation fields in an intermediary. Both new peers falling back to legacy because of altered negotiation can time out; they do not skip verification.

After successful negotiation:

| Flow / server mode | Initiator | Request validator / incoming business listener |
| --- | --- | --- |
| `-` / 1 | Client | Server |
| `+` / 2 | Server | Client |

Only the initiator consumes an idle verification connection locally. The receiver consumes the matching ID once, checks the existing certificate fingerprint, and queues an acknowledgement before completing its business gate. The initiator completes only after a matching acknowledgement. Both sides then retain one buffered, idempotent completion notification.

The original control frame is retained:

```json
{"action":"verify","id":"<connection-id>","fp":"<fingerprint>"}
```

Only negotiated new peers send the acknowledgement extension:

```json
{"action":"verify","id":"<same-id>","fp":"<same-fingerprint>","ack":true}
```

The acknowledgement must match a pending local request's ID and fingerprint. Unsolicited or mismatched acknowledgements, acknowledgements in legacy mode, missing certificate state, mismatched certificates, conflicting requests and missing acknowledgements cancel the run. Identical requests and acknowledgements do not consume extra connections or duplicate completion.

## Legacy peer sequencing

An unchanged legacy peer initiates its own verification after the original reporting delay. The updated endpoint, in either server or client role, waits for and validates that request first. This removes the legacy-owned ID locally. It then selects a different idle ID and sends the original verification frame back to the legacy peer. No acknowledgement extension is sent to an old peer.

This preserves the legacy reciprocal comparison while preventing the updated side from independently choosing the same ID. Legacy implementations retain their own known lifecycle/security limitations; interoperability here is not a guarantee that an old binary is stable or secure.

## Completion and cancellation

Verification state belongs to one `InitContext` run: initiation, peer-validation readiness, pending ID/fingerprint, completion and acknowledgement deadline. Captured callbacks use that state and its cancellation function, so late completion cannot release a later run's gate. The completion gate is buffered once; a non-listening endpoint does not block trying to notify it.

Legacy-peer waiting and acknowledgement waiting use a bounded budget of `PoolGetTimeout + ReportInterval` (10 seconds with current defaults). Individual pool operations retain `PoolGetTimeout`. Cancellation aborts waits and queued writes. This is scoped verification-state isolation, not a claim that the entire pre-existing Common/pool restart lifecycle is race-free; TNV-004 remains open.

## Handshake response commit

A separate change ensures that a newly implemented server serializes the complete configuration, sets its Content-Length and flushes it before signalling that the HTTPS listener can be closed and replaced. A single accepted request owns the transition. Invalid authentication cannot claim it; a failed response write releases the claim. This addresses the observed early-close EOF path on new servers. Unchanged old servers do not acquire this fix.

See [fix evidence](tnv-002-fix.md), [M1 baseline](m1-findings.md) and [defect ledger](defects.md).
