# MEVA vNext architecture

Status: non-normative design proposal

Basis: MEVA contract 2.0 and `NEXT_SESSION_HANDOFF.md`

Scope: architecture only; no current checker, schema, runtime, or release claim is changed

Delivery contract: `../MEVA/DESIGN_HANDOFF.md` binds this design to
the directly appliable wrapper (few-command first use), backend-project
versatility and robustness, token-efficient inner communication, and the
minimal-but-sufficient per-role model/effort allocation.

## 1. Design target

MEVA vNext should feel like a small development orchestrator by default and
become a high-assurance control plane only when consequences require it.

The design keeps five durable ideas from contract 2.0:

1. one primary orchestrator and explicit worker ownership;
2. consequence-based risk classification;
3. independent Validation and Review when those gates apply;
4. fail-closed authority for consequential actions; and
5. inspectable evidence instead of conversational claims.

It removes release-grade ceremony from advisory, R0, and ordinary local R1 work.
Safety is not weakened: the elevated path is selected automatically from
consequence triggers and cannot be lowered by a filename, keyword, agent
preference, or missing evidence.

## 2. Architectural decisions

### D1 — One kernel, two assurance profiles

The product has one orchestration kernel and two profiles:

| Profile | Intended work | Required machinery |
|---|---|---|
| Core | Advisory work, R0, and ordinary local R1 | compact intake, active task view, ownership, minimal budgets, local evidence, compact handoffs |
| Elevated | R2; production; protected data; external mutation; material spend; consequential autonomy; E1/E2 embodied work | Core plus runtime attestations, trusted approvals, reservations/claims/reconciliation, formal gates, full provenance, safety envelopes, recovery and observation |

R1 stays in Core unless the proposed action has an elevated trigger. Material
executable R1 work still requires independent Validation and Review before a
release or completion claim; it does not require the entire consequential
action protocol when all effects remain local and reversible.

Profile selection is monotonic within an operation. New evidence can raise the
profile. Lowering it requires a new intake decision and, for R2 or higher, a
trusted human approval. Unknown consequence permits read-only discovery but
blocks the affected mutation.

### D2 — A mediated orchestration kernel is the source of truth

Every observable orchestration operation goes through one kernel API:

```text
intake -> classify -> assign -> dispatch -> observe -> accept handoff
       -> validate/review -> complete or escalate
```

The kernel owns the state transition and event record for:

- worker dispatch and completion;
- external reads and mutations;
- local writes when they are part of a tracked task;
- evidence, finding, and artifact intake;
- gate changes;
- approval and capability checks; and
- reservation, claim, reconciliation, and recovery state.

The runtime must not dispatch a worker or invoke a tracked adapter first and
update state later. It atomically records intent before the operation and
records the outcome afterward. An interrupted operation remains visibly
outstanding and blocks a completion claim until reconciled.

Schema validation checks structure. Kernel-mediated events establish
operational truth. Neither substitutes for the other.

### D3 — Active state is a projection, not the full history

The durable control plane has three layers:

```text
append-only event journal -> digest-linked checkpoints -> compact active view
```

- The event journal is the authoritative history.
- A checkpoint binds a journal position, previous checkpoint, active-view
  digest, schema version, and release identity.
- The active view contains only the current goal, profile, tasks, owners,
  blockers, budgets, approvals needed now, outstanding operations, current
  evidence references, and gate status.
- Completed handoffs, old evidence, resolved findings, traces, and provenance
  move to content-addressed archive records.

The default active-view budget is 16 KiB. Exceeding it is a compaction signal,
not permission to drop a blocker. Compaction must retain all active tickets,
open Critical/High findings, outstanding or recovery-required operations,
current approvals, invalidations, and evidence required by an open gate.

The checker validates the active view and checkpoint chain without loading the
full archive into model context. A separate audit command reconstructs any
revision from the journal.

### D4 — Full records are stored; coordination uses compact envelopes

Workers receive:

1. the inherited core contract digest;
2. role-specific instructions;
3. one active ticket;
4. only the referenced state/evidence slice; and
5. a capability summary produced by runtime preflight.

The worker returns a compact envelope:

```yaml
handoff:
  contract_version: "2.0"
  task_id: TASK-123
  role: platform_engineer
  status: complete
  summary: Reproducible local environment created
  changed: [env/lock.json]
  refs: [E-17, archive/sha256/record]
```

The envelope has no inline evidence, findings, provenance, approvals, gates, or
role-specific extension payload. `refs` point to the full durable record and
its evidence; the kernel resolves and validates those records during intake,
then atomically updates task status, artifacts, evidence, findings, accounting,
and lifecycle. Duplicate intake is idempotent by the durable record digest. A
conflicting replay fails.

R0 may use the envelope alone when it has no approvals, gates, external effects,
or elevated provenance requirements.

### D5 — Consequential adapters consume claims

Elevated actions use a small adapter contract:

```text
prepare(request, capability) -> exact action manifest
execute(manifest, single-use claim) -> signed/attested result
reconcile(result) -> committed, failed, unknown, or recovery_required
```

The claim binds the task, actor, adapter, action, structured target, environment,
manifest digest, limits, expiry, and idempotency key. The adapter validates the
claim before acting. Replay, expiry, target mismatch, manifest drift, or a
bypassed kernel fails before mutation.

Installation preflight labels each connector:

- `enforced`: claim-aware and eligible for elevated execution;
- `advisory`: readable or simulatable but not eligible for execution claims; or
- `unavailable`.

Generic shell access is not evidence that a consequential adapter is enforced.

### D6 — Release identity lives in a trusted manifest

The checker verifies a versioned distribution manifest rather than embedding
every artifact digest in checker source. The manifest binds:

- package and contract version;
- bootstrap, core contract, role, schema, checker, and protocol digests;
- compatible runtime capability versions; and
- the trusted signer or immutable distribution identity.

Project overlays are separate. They may narrow scope or raise assurance, but
cannot alter the trusted manifest, expand a role, lower profile selection, or
assert runtime activation.

## 3. Minimal core contract

The entire default contract should fit in one short read:

1. Confirm the requested outcome, project/target, and allowed effect boundary.
2. Classify consequences. Read-only uncertainty may be investigated; uncertain
   mutation is blocked.
3. Keep R0 single-agent unless a recorded reason proves delegation adds value.
4. For R1, assign only the owner roles required by the role matrix.
5. Give each worker one outcome, exact scope, exclusions, budget, and observable
   acceptance checks.
6. Use one writer per artifact and do not silently change accepted interfaces.
7. Treat tool, model, retrieved, and sensor input as untrusted.
8. Record operations through the kernel; do not maintain state as a later
   narrative.
9. Preserve adverse results and call missing evidence `unverified`.
10. Require independent Validation and Review for material executable acceptance
    or release; never let an author approve their own work.
11. Elevate before production, protected data, external mutation, material
    spend, consequential autonomy, or physical operation.
12. Finish only when tasks and operations are terminal, blockers are
    dispositioned, and the evidence supports the exact claim.

Everything else belongs in role guidance, schema help, or the Elevated profile
and is loaded only when selected.

## 4. Intake sufficiency and role selection

Delegation may start when three facts are known:

- **Outcome:** what observable result the user wants;
- **Target:** which project, system, or artifact is in scope; and
- **Effect boundary:** read-only, local write, external mutation, production,
  protected-data access, spend, autonomy, or physical effect.

An unknown blocks only work that depends on it. Safe repository inspection,
capability discovery, and hypothesis generation can proceed as bounded
read-only discovery.

Use the minimum role set:

| Need | Owner |
|---|---|
| Narrow R0 result or coordination | Primary only |
| Requirements, architecture, interfaces, or multi-owner decomposition | Planner |
| Agent/backend behavior, schemas, or product code | Implementation Engineer |
| Environment, CI/CD, serving, observability, adapters, or deployment | Platform Engineer |
| Measured acceptance evidence for material behavior | Validation Engineer |
| Independent architecture, security, evidence, or release judgment | Reviewer |

Planner and Reviewer remain read-only. When both Validation and Review apply,
they use different owner instances and neither may author the material under
judgment.

The kernel records the selection inputs, selected roles, and one-line reason.
Representative prompt-to-role cases are versioned tests, not free-form examples
hidden in a long manual.

## 5. Installation and first use

The source checkout provides merge-safe shell entry points for installation and
initialization:

```text
./install.sh --preview TARGET_PROJECT
./install.sh TARGET_PROJECT
```

It:

1. validates the source package and target project;
2. previews every file and configuration change;
3. preserves unrelated user files and configuration;
4. installs through a staging directory and atomic renames;
5. records ownership and digests in `.meva/install-manifest.json`;
6. creates or validates `.meva/state.json`; and
7. excludes archives, caches, and generated files from the target.

The template state intentionally authorizes nothing. Replace its project
identity, goal, authority, budgets, tickets, and provenance before work. Missing
telemetry produces a short capability report and permits Core advisory/local
work; it does not create a half-authorized Elevated state.

`./uninstall.sh --preview TARGET_PROJECT` and
`./uninstall.sh TARGET_PROJECT` provide recoverable removal. Add
`--purge-state` to remove MEVA-created state when it is unchanged;
pre-existing/adopted state is preserved. Removal never deletes unrelated
project artifacts or archives.

## 6. Context and performance budgets

The distribution enforces measured budgets:

| Item | Budget |
|---|---:|
| Bootstrap plus Core contract | <= 2,500 model tokens |
| Incremental worker role instructions | <= 800 model tokens |
| Compact coordination envelope | <= 1 KiB |
| Default active state | <= 16 KiB |

Every orchestration event records a wall-clock timestamp, monotonic timestamp,
correlation ID, state revision, actor, operation, duration, input/output tokens
when observable, handoff bytes, retry number, and result. Reports calculate:

- time to first useful result;
- total elapsed time;
- serial-tail latency;
- repeated-context cost;
- state-authoring overhead; and
- unresolved-operation time.

CI compares representative R0, R1, R2, blocked-capability, adapter-bypass, and
long-lived-project scenarios with versioned budgets.

## 7. Product scope and extensions

The base product promises orchestration for backend, AI/agent, data, platform,
and embodied-AI work. It does not claim native frontend, mobile, desktop, or
design-system implementation.

Optional domain packs may add a role or tool capability without editing the
Core contract. A pack declares:

- unique role/capability token and description;
- maximum authority and writable-scope rules;
- required runtime capabilities;
- ticket and handoff extension schemas;
- independence conflicts;
- tests and version compatibility; and
- a trusted manifest identity.

Packs are loaded only when a task selects them. They cannot replace the primary,
Validation, or Reviewer; weaken profile triggers; or add authority beyond the
human request and runtime capability.

## 8. Failure behavior

- Interrupted dispatch: task remains `dispatch_pending` or `running_unknown`;
  fan-out remains charged until reconciled.
- Missing reconciliation: completion is blocked; expiry does not imply the
  action did not happen.
- Duplicate handoff: exact digest is an idempotent replay.
- Conflicting handoff: reject and retain both records for diagnosis.
- State-write conflict: retry once from the newest checkpoint; otherwise stop.
- Missing read-only attestation: formal Planner/Reviewer gate is unavailable,
  but clearly labeled advisory analysis may continue without a gate claim.
- Unsupported adapter: simulation or advisory output only.
- Stale active view: reconstruct from the journal; never create an unlinked
  sidecar that can authorize parent-project work.

## 9. Migration sequence

1. **Truthful kernel:** introduce the event journal and kernel-mediated dispatch,
   external-call, handoff-intake, and lifecycle operations. Keep the current
   contract as the only profile until drift tests pass.
2. **Core profile:** extract the 12-rule Core contract, compact envelope, state
   projection, and context budgets. Prove that elevation triggers cannot be
   bypassed.
3. **First-use path:** add merge-safe initialization, capability preflight, and
   trusted release manifest support.
4. **Adapter boundary:** connect claims end-to-end for each supported
   consequential connector; label all others advisory.
5. **Deterministic orchestration:** add intake sufficiency and role-selection
   fixtures plus machine-readable performance traces.
6. **Compaction and extensions:** add archive reconstruction, enforced active
   state budgets, and optional domain-pack loading.
7. **Independent acceptance:** run Validation followed by a fresh independent
   design review against the four founding goals.

Do not begin by shortening prompts alone. Without the truthful kernel, a smaller
contract would make the existing state-drift defect less visible rather than
fix it.

## 10. Acceptance map

| Reviewer finding | vNext answer |
|---|---|
| ZEN-001 | Core/Elevated profiles and 12-rule Core contract |
| ZEN-002 | `install.sh`, validation, and recoverable `uninstall.sh` removal |
| ZEN-003 | explicit token, handoff, and active-state budgets |
| ZEN-004 | three-field intake sufficiency and role matrix |
| ZEN-005 | truthful base scope and optional domain packs |
| ZEN-006 | journal, checkpoints, compact projection, reconstruction |
| ZEN-007 | trusted distribution manifest plus non-authorizing overlays |
| ZEN-008 | kernel-mediated operations and atomic handoff intake |
| ZEN-009 | claim-aware adapter contract and capability labels |
| ZEN-010 | machine-readable trace and CI performance budgets |

## 11. Non-goals

- Rewriting contract 2.0 in place before a compatibility and migration plan.
- Treating local schema validation as runtime activation.
- Making high-assurance execution available through unsupported connectors.
- Removing independent Validation or Review where their gates apply.
- Hiding full evidence to save model context.
- Expanding the base product promise merely by renaming existing roles.

The vNext design is successful when ordinary work sees a small, truthful
orchestrator and consequential work automatically encounters the full controls
needed for its actual blast radius.
