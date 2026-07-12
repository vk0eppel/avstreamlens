# Keep window-close check/reset sequencing in the parent, not per-substate

## Status

accepted

## Context

`CaptureState` owns four protocol-family substates (`DanteState`, `IgmpState`,
`PtpState`, `AvbState`), each with its own `check_*` diagnostics and a
`reset_window`. Every Window, `end_of_window` runs **all** checks first and then
calls `reset_window` (which fans out to each substate's `reset_window`) **last**.
The ordering invariant — every check before any reset — is documented in ~40
lines of "Must run AFTER …" comments and enforced only by call-site order.

Issue #84 proposed giving each substate a single `close_window() -> Vec<Alert>`
that does check-then-reset internally, so the parent stops sequencing the two and
the ordering contract moves inside the module that owns the state.

## Decision

**Do not** bundle check+reset per substate. Keep the parent's "all checks, then
all resets" sequencing. The substates are not independent along the window-close
axis:

- `DanteState::check_follower_census(&self, ptp: &PtpState)` reads
  `PtpState::v1_followers`, which `PtpState::reset_window` prunes. A Dante check
  reads Ptp's per-window state.
- `IgmpState::check_multiple_queriers(&self, health: &mut NetworkHealth, …)`
  writes `NetworkHealth`, whose `multiple_queriers_this_window` flag the parent
  (not `IgmpState`) resets.

Because `DanteState`'s check reads `PtpState`, a per-substate `close_window` would
force `ptp.close_window()` to run **after** `dante.close_window()` — relocating
the exact cross-module ordering constraint #84 set out to remove, not
eliminating it. And the naive version (each substate resets right after its own
checks) is an outright bug: `ptp.close_window()` would prune `v1_followers`
before the Dante follower census reads them. None of the four substates is
cleanly self-contained along this axis.

## Considered options

- **Per-substate `close_window` (the proposal).** Rejected: cross-substate reads
  (`dante`→`ptp`) and a shared-state write (`igmp`→`NetworkHealth`) mean it either
  reintroduces an inter-`close_window` ordering constraint or corrupts the
  follower census by pruning before the read.
- **Partial `close_window` for only the "self-contained" substates.** Rejected:
  once the cross-cutting checks (`check_follower_census`, `check_multiple_queriers`)
  must stay parent-sequenced, the goal ("parent stops sequencing") is not met, and
  the result is a more confusing split — some resets inside the substate, some in
  the parent.
- **Keep parent sequencing, harden the invariant structurally (status quo +).**
  The single `reset_window` fan-out called last from `end_of_window` already
  concentrates the ordering in one place. This is where any future hardening (a
  debug assertion, a type-state token) should go — not a per-substate split.

## Consequences

The ~40 lines of "Must run AFTER …" comments in `reset_window` stay load-bearing
documentation of a real, cross-module invariant. A future reader may see the
substates each own a `reset_window` but **not** a `close_window` and wonder why
the checks live on the parent's `end_of_window` — this is deliberate: the checks
have cross-substate reads that the "all checks, then all resets" order exists to
satisfy. Revisit only if the cross-substate reads are removed (e.g. the Dante
follower census stops reading `PtpState`, and querier conflict state moves off
`NetworkHealth` onto `IgmpState`).
