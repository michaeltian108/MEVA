# MEVA contract v2

MEVA is a project-local orchestration contract for backend, AI/agent, data,
platform, and embodied-AI work. It provides one automatically activated primary
orchestrator and exactly five bounded worker roles. It does not provide frontend
implementation.

`AGENTS.md` is the normative behavioral manual and bootstrap.
`contracts/meva.schema.json` is the sole machine authority for structures and
canonical tokens. `.meva/state.json` is the active durable control-plane
record. Conversation and response handoffs do not replace that JSON state.

Every role uses the same compact YAML envelope: `contract_version`, `task_id`,
`role`, `status`, `summary`, `changed`, and `refs`, plus one actionable `open`
condition for non-complete outcomes. The envelope is bounded and schema-closed;
it points to durable state/evidence instead of repeating provenance, gates,
approvals, risks, or role-specific payloads. Canonical handoff details remain
auditable in state or referenced artifacts, so compactness does not reduce
assurance.

## Requirements

- Python 3.9 or newer; the checker uses only the standard library.
- A current Codex release supporting the documented `agents.enabled`,
  `agents.max_concurrent_threads_per_session`, and `agents.interrupt_message`
  configuration keys.
- A trusted project and a fresh session after activation files change.
- An external/runtime enforcement layer appropriate to the task's consequences.

Project files, prompts, schema validation, and checker results are defense in
depth. They do not prove complete runtime security, sandboxing, approval
authenticity, action accounting, or physical safety enforcement.

## Install into an existing local project

MEVA is installed into the project where Codex will work; it is not installed
globally. There are two directories involved:

- **MEVA source** — the checkout containing this README.
- **Target project** — the existing local project that should receive MEVA.

They may be unrelated directories. GitHub is only one way to obtain the
MEVA source; if the target project is already on your machine, leave it in
place and point the install at its path. If you downloaded or cloned this
source, use the extracted checkout as `MEVA_SOURCE`; the installation steps
are the same.

Set the paths, replacing both placeholders with absolute paths:

```sh
MEVA_SOURCE=/path/to/MEVA
TARGET_PROJECT=/path/to/my-project
```

When your terminal is already in the target project, `TARGET_PROJECT=$(pwd)` is
convenient.

From the MEVA checkout, copy the contract and support files into the target
(the commands use absolute paths, so the current directory does not matter):

```sh
mkdir -p "$TARGET_PROJECT/.codex/agents" \
  "$TARGET_PROJECT/contracts" \
  "$TARGET_PROJECT/templates" \
  "$TARGET_PROJECT/tools" \
  "$TARGET_PROJECT/docs" \
  "$TARGET_PROJECT/tests/conformance"

cp -R "$MEVA_SOURCE/.codex/agents/." "$TARGET_PROJECT/.codex/agents/"
cp -R "$MEVA_SOURCE/contracts/." "$TARGET_PROJECT/contracts/"
cp -R "$MEVA_SOURCE/templates/." "$TARGET_PROJECT/templates/"
cp -R "$MEVA_SOURCE/tools/." "$TARGET_PROJECT/tools/"
cp "$MEVA_SOURCE/docs/reviewer-handbook.md" "$TARGET_PROJECT/docs/"
cp -R "$MEVA_SOURCE/tests/conformance/." "$TARGET_PROJECT/tests/conformance/"

# These checks copy only missing files; merge existing destinations manually.
if [ ! -e "$TARGET_PROJECT/AGENTS.md" ]; then
  cp "$MEVA_SOURCE/AGENTS.md" "$TARGET_PROJECT/AGENTS.md"
fi
if [ ! -e "$TARGET_PROJECT/.codex/config.toml" ]; then
  cp "$MEVA_SOURCE/.codex/config.toml" "$TARGET_PROJECT/.codex/config.toml"
fi
```

The copy block assumes these MEVA-owned support files are not already in the
target. If a destination already exists, compare it with the source and merge
or preserve it rather than replacing unrelated project content.

Review and merge these two files into the target rather than overwriting
existing project content:

```text
$MEVA_SOURCE/AGENTS.md           -> $TARGET_PROJECT/AGENTS.md
$MEVA_SOURCE/.codex/config.toml  -> $TARGET_PROJECT/.codex/config.toml
```

If the target has no `AGENTS.md` or `.codex/config.toml`, copy them directly.
Otherwise, preserve unrelated instructions and configuration, and keep only
the documented Codex keys supported by the installed release. Delegation depth
is enforced by the durable task budget and checker, not by a project
configuration key.

Initialize canonical state from the target project root. Do this only when the
target does not already have `.meva/state.json`; preserve and validate an
existing state file instead of replacing it:

```sh
cd "$TARGET_PROJECT"
mkdir -p .meva
if [ -e .meva/state.json ]; then
  echo "Preserving existing .meva/state.json; validate it in place."
else
  cp "$MEVA_SOURCE/templates/project-state.json" .meva/state.json
fi
```

Replace the template project identity, goal, consequence-based risk rationale,
authority, budgets, tickets, and provenance before work. Do not add absolute
machine-specific paths. The unmodified template intentionally authorizes
nothing and leaves runtime activation unverified. A primary handling an explicit
current human request may initialize or minimally refresh this local control
plane before activation telemetry exists. That bootstrap may only record or
narrow the current authority and bind a Core local ticket; it does not authorize
product work by itself.

## Validate

Run static package conformance:

```sh
python3 tools/meva_check.py check-package --root .
```

For machine validation of a parsed handoff envelope, use the same checker (the
wire YAML is presentation; the decoded mapping is normative):

```sh
python3 tools/meva_check.py validate-handoff handoff.json
```

The output separates:

- `static_package`: `pass` or `fail`;
- `runtime_activation`: `pass`, `fail`, or `unverified`.

A static pass never upgrades missing runtime telemetry. Without a live state and
runtime-owned attestation, activation remains `unverified`. This blocks
runtime-dependent assurance and consequential operations, but it is not a
global stop state. The bounded Core local lane below remains available for
explicitly authorized, reversible local R0 work.

Validate active state:

```sh
python3 tools/meva_check.py validate-state .meva/state.json
```

The checker rejects malformed structure, duplicate JSON keys, unknown fields
outside `extensions`, non-finite or negative accounting, noncanonical paths,
invalid canonical tokens, illegal/cyclic dependencies,
illegal lifecycle transitions, incomplete invalidation, read-only writes,
authorship conflicts, out-of-scope paths, untrusted approvals, hard-limit
excess, and priority attempts to weaken review blockers.

Check package plus live activation:

```sh
python3 tools/meva_check.py check-package \
  --root . \
  --state .meva/state.json \
  --role implementation_engineer \
  --task-id TASK-001
```

Activation can pass only when fresh runtime-owned telemetry binds the effective
project, role, ticket, runtime, model, provider, policy/config/manual/schema/role
digests, permissions, and expiry. Stale, self-authored, mismatched, broader, or
unknown relevant evidence yields `fail` or `unverified`.

The package checker binds both frozen protocols, locks, and harnesses to
immutable embedded digest anchors. State `artifact_digests` are optional
redundancy, but any declared mismatch fails activation. A local coordinated edit
and matching self-hash is not a trusted release anchor.

## Action reservation and reconciliation

Before a write or consequential tool action, validate the current state and
proposed action:

```sh
python3 tools/meva_check.py preflight \
  --state .meva/state.json \
  --task-id TASK-001 \
  --role implementation_engineer \
  --action edit_assigned_files \
  --action-kind ordinary \
  --path src/service.py \
  --environment local \
  --action-chain-steps 1
```

Preflight intersects human authority, role maximum, the ticket, and
runtime-attested capabilities. It also enforces exact writable scope and the
ticket's current budget, call, fan-out, delegation-depth, retry, alternative,
and action-chain counters. It is diagnostic compatibility only and returns
`authorizes_consequential_action: false`.

If no matching runtime attestation exists, preflight can classify a direct Core
local write as eligible without pretending activation passed:

```sh
python3 tools/meva_check.py preflight \
  --root . \
  --state .meva/state.json \
  --task-id TASK-LOCAL-001 \
  --role implementation_engineer \
  --action edit_assigned_files \
  --action-kind ordinary \
  --path src/service.py \
  --target-expected-digest CURRENT_SERVICE_SHA256 \
  --environment local
```

`local_execution_eligible: true` requires an active R0 ticket, a
write-capable role, exact current human authority, public/internal data,
local-only project-write scope, zero external-call capacity, no approval or
E1-E3 physical requirement, no matching stale/conflicting attestation, no
pending atomic action, explicit trusted `project_write` metadata,
`core_local_rollback: restore_preimage`, no metered/delegated/retry/chained
increments, and an exact existing-file preimage inside the in-root non-symlink
target.
When authority expiry is unknown, the state must explicitly bind it to the
current interaction with `authority.extensions.core_local_authority: true`.
That marker and the task metadata are untrusted predicates, not proof of human
authority; a direct current user instruction must also be present in the live
session.
The output retains `authorizes_consequential_action: false` and includes a
`local_action_binding` over the state revision and digest, task, role, root,
path, and preimage. The eligible existing-file replacement proceeds only when
the current human authority and host workspace tool atomically compare that
binding. It cannot count as R1 completion or support production, external,
physical, release, or formal-independence claims. `reserve-action` and
`claim-action` remain strict and require verified runtime activation.

`reserve-action` records capacity but does not authorize execution. The caller must
provide the exact current state digest, state revision, and ledger revision, a
trusted action kind/effect, canonical structured target, and finite nonnegative
reservation amounts:

```sh
STATE_DIGEST="$(shasum -a 256 .meva/state.json | awk '{print $1}')"
python3 tools/meva_check.py reserve-action \
  --state .meva/state.json \
  --idempotency-key CHANGE-TASK-001-SERVICE \
  --task-id TASK-001 \
  --role implementation_engineer \
  --action edit_assigned_files \
  --action-kind ordinary \
  --effect project_write \
  --target-kind file \
  --target-id src/service.py \
  --path src/service.py \
  --target-expected-digest CURRENT_SERVICE_SHA256 \
  --environment local \
  --cost 1 \
  --expected-state-revision 3 \
  --expected-ledger-revision 0 \
  --expected-state-digest "$STATE_DIGEST" \
  --expires-at 2030-01-01T00:10:00Z
```

Even on exit 0, reserve output has `authorizes_consequential_action: false`.
External reads reserve at least one call. Production project writes also require
the task's exact active approval at reservation and claim.
Immediately before one adapter execution, atomically consume the reservation:

```sh
python3 tools/meva_check.py claim-action \
  --state .meva/state.json \
  --task-id TASK-001 \
  --role implementation_engineer \
  --reservation-token RESERVATION_TOKEN \
  --expected-request-digest REQUEST_DIGEST \
  --claim-id CHANGE-TASK-001-SERVICE-CLAIM
```

Only the first claim can report `authorizes_consequential_action: true`; claim
replay reports false. After the action, reconcile actual use against the
immutable request digest:

```sh
python3 tools/meva_check.py reconcile-action \
  --state .meva/state.json \
  --reconciliation-id CHANGE-TASK-001-SERVICE-RESULT \
  --task-id TASK-001 \
  --role implementation_engineer \
  --reservation-token RESERVATION_TOKEN \
  --expected-request-digest REQUEST_DIGEST \
  --execution-status succeeded \
  --actual-cost 0.8 \
  --outcome-digest SHA256_OF_OUTCOME
```

Exit 0 means committed or an exact idempotent reconciliation replay; 1 means
denied/malformed, 2 means unverified or migration required, and 3 means lock/CAS
conflict. A successful reservation persists its canonical request digest,
selected permission-attestation ID, and ticket-bound capability identity.
Repeating the same idempotency key and exact request returns the existing token;
divergent reuse conflicts, and replay rechecks current authority without
authorizing execution. Each reservation consumes one action-chain step up to its
discrete hard limit. Committed plus pending metered resources drive the
70/90/100-percent controls. The
state file must resolve inside `--root` unless an
explicit `--trusted-state-root` is supplied. Target revision/digest
preconditions should be supplied whenever the target resource exposes them;
unsupported revision claims, stale digests, and resolved/symlink scope escapes
reject. Expiry cannot exceed current human authority or runtime attestation, and
atomic commands reject caller-controlled `--now`.
Overrun and unknown execution are durably charged and marked
`recovery_required`. Expiry does not auto-release a possibly executed action.
Reconciliation keys on the immutable reservation/request rather than unrelated
global ledger progress, accepts a fresh current accounting attestation, and
validates the prospective state before commit.
The adjacent POSIX advisory lock, atomic rename, and directory fsync do not prove
network-filesystem semantics, Windows support, or that every runtime tool path
uses this boundary; those remain runtime/platform controls.

At 70 percent, notification and re-estimation are required. At 90 percent,
fan-out and nonessential work are denied. At 100 percent, ordinary work is
denied while bounded cleanup and emergency safe-stop remain eligible. A hard
limit is never exceeded.

## Approval verification

Resolve approval IDs through a trusted external/runtime source, persist the
verification record, then require exact action, ordered structured scope,
environment, limits, active status, and unexpired UTC expiry:

```sh
python3 tools/meva_check.py verify-approval \
  --state .meva/state.json \
  --approval-id APPROVAL-001 \
  --action deploy_release \
  --scope service/api \
  --environment staging \
  --limits-json '{"max_cost":null,"max_compute_units":null,"max_wall_time_seconds":600,"max_external_calls":0,"max_action_chain_steps":10,"physical_envelope":{},"extensions":{}}' \
  --now 2030-01-01T00:00:00Z
```

An approval written only by an agent or response is self-asserted and rejected.
Substring/superset scope, mismatch, revocation, and `now >= expires_at` reject.

## Review evaluation

Evaluate the durable review without allowing P0-P3 remediation priority to alter
severity or blocking:

```sh
python3 tools/meva_check.py evaluate-review \
  --state .meva/state.json
```

Open critical findings are P0 and block. Open high findings are P0 or P1 and
block. Valid exact structured risk acceptance can disposition a blocker where
permitted.
Priority never changes severity, disposition, approval requirements, or gate
behavior.

Structured RV2 risk acceptance exactly binds the finding revision and affected
operation and is forbidden for critical safety, emergency-stop, deterministic
safety, live embodied, and other non-waivable findings. Corresponding approval
limits may be narrower than the affected operation but never broader or
mismatched. A formal review cannot pass without nonempty current artifact and
evidence targets plus runtime-owned read-only and independence proof. Legacy
extension-empty review and critical/high disposition records remain diagnostic
and non-gating only.

## Release evidence

Installed consumer packages use `check-package` and do not require Validation
reports. Release candidates additionally use:

```sh
python3 tools/meva_check.py check-release --root .
```

`check-release` fails when either Validation-owned report is missing, stale,
has absent or escaping digest bindings, records absent or inexact commands,
results, outputs, or conclusions, or no longer binds the product artifacts. The
original report must expose an exact
passing post-WP4 43-test suite; the RV2 report must expose exact passing
43/30/73 runs; and the assurance report must expose exact passing 38/111 runs
bound to its frozen protocol and harness. The final-review report must disclose
the three superseded unsafe legacy positives, pass 16/16 new cases, and pass the
corrected 124/124 aggregate. Product code never regenerates Validation reports.

## Activation workflow

1. Copy and merge the package.
2. Initialize and validate `.meva/state.json`.
3. Trust the project only after reviewing `AGENTS.md`, `.codex/config.toml`,
   worker prompts, the checker, and any project overlay.
4. Start a fresh Codex session so bootstrap/config/role changes can load.
5. Obtain runtime-owned activation and effective-permission telemetry.
6. Record current provenance digests and bind the active ticket.
7. Run `check-package` with the live state and require the result appropriate to
   the task. Consequential work requires verified activation.
8. For R0 Core local progress, run the bounded preflight and execute only an
   atomic existing-file compare-and-swap through the host workspace tool; record
   at most one aggregate task summary at close. For R1, consequential, or
   Elevated work, use `reserve-action`, then the single-use `claim-action`,
   immediately before execution and `reconcile-action` immediately afterward.

Managed policy and actual runtime permissions can override project sandbox
defaults. For Reviewer and Planner, inability to prove effective read-only
enforcement invalidates their gate output. For production, protected data,
material spend, autonomous action, or embodied operation, use independent
external enforcement, trusted approval resolution, audit logging, and the
non-waivable controls in `AGENTS.md`.

## Recovery

Treat state updates as one-writer atomic revisions. Preserve the last validated
state and digest before replacement. On malformed state, invalidation mismatch,
unknown consequential authority, or checker failure, stop ordinary work,
preserve evidence, and allow only bounded diagnosis, cleanup, or emergency
safe-stop as the manual permits.
