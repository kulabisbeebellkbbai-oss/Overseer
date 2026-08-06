# Reusable Approval Facility Pause Checkpoint

Date: 2026-08-05

Branch: `feature/reusable-approval-facility`

This project is paused at the user's request because of an approaching usage
limit. The branch is a source-only checkpoint. It is not approved for merge,
deployment, restart, protected-gateway changes, or DonutHole provisioning.

## Completed boundary

Capability C Task 4 is complete and independently reviewed. The reviewed
TheUnderdark runtime-attestation commit is
`98d02c193e8fa00bf232b0f7adcfeb41e2e1e107`.

## Incomplete boundary

Capability C Task 5 is work in progress. The checkpoint contains:

- a strict read-only behavior-acceptance module and focused tests;
- partial runtime-installation hardening and exact systemd runtime identity
  arguments;
- tests that expose remaining runtime normalization and integration work.

Focused acceptance verification passed with 10 tests. The runtime/provisioning
suite is not green. The first reproducible failure follows 65 passes and is in
the staging-cleanup convergence test, where the test boundary stub does not
model the production normalizer's root-mode change. Other failures were visible
in the interrupted broader run and must be re-enumerated on resume.

## Resume checklist

1. Verify the active pause claim and re-establish checkout ownership.
2. Re-run the two focused Task 5 suites before editing.
3. Finish the descriptor-relative runtime normalizer and its adversarial race,
   device, depth, count, hardlink, special-file, and `lib64` tests.
4. Finalize non-editable dependency installation and controlled attested-source
   imports.
5. Implement the v3 plan/header acceptance binding while retaining v2 as
   immutable read-only history that requires a successor.
6. Integrate the exact acceptance runner without collapsing safe failure codes.
7. Run focused, affected, full, and cross-repository tests; obtain both Terra
   reviews; freeze the commit; obtain final Sol security approval.

## Lock and safety state

Overseer checkout claim
`claim.overseer.reusable-approval-facility.pause.20260805` is active for resource
`checkout.overseer.feature.reusable-approval-facility` with no expiry. Its
release condition is explicit user resumption plus re-established checkout
ownership.

No live action was performed.
