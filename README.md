# MEVA

### Minimal, Evolving, Versatile orchestration for Codex projects

MEVA turns a request into accountable, inspectable progress.

It gives Codex projects a small operating layer: one primary orchestrator keeps
the goal, decisions, ownership, and next step together, then brings in only the
specialists that make the work better. The result is less agent sprawl, clearer
handoffs, and evidence you can actually review.

MEVA is installed inside the project where Codex works. It does not replace
your application, require a hosted service, or force a new framework on your
team.

## Why the name fits

### Minimal

Start with a single orchestrator and a small set of optional specialists. MEVA
keeps the everyday path light: no global daemon, no mandatory multi-agent
ceremony, and no pile of services to operate. More control is introduced only
when the consequences of the work justify it.

### Evolving

Projects change. MEVA keeps the current goal, decisions, evidence, and open
questions with the project so the team can pick up where it left off. It can
begin with a simple local task and grow into stronger validation, review, and
approval workflows as the work becomes more consequential.

### Versatile

The same foundation works across backend services, AI and agent systems,
model-serving, data, platform, and embodied-AI projects. MEVA is deliberately
project-local and tool-agnostic, so it can sit beside the code and practices
you already use.

## What using MEVA feels like

```text
Your request
    ↓
MEVA Orchestrator — understands the outcome and owns the plan
    ↓
Only the right specialists — plan, build, operate, test, or review
    ↓
Clear evidence — what changed, what passed, and what still needs attention
```

The primary orchestrator is not a worker to summon. It is the accountable
coordinator. The five bounded workers are used only when their perspective or
independence adds value:

| Specialist | Brings focus to |
| --- | --- |
| Planner | Goals, scope, interfaces, risks, and acceptance criteria |
| Implementation Engineer | Product behavior, integrations, and code-level tests |
| Platform Engineer | Environments, dependencies, delivery, and observability |
| Validation Engineer | Test methods, scenarios, measurements, and regressions |
| Reviewer | An independent look at the result and its readiness |

## Install in an existing project

### Requirements

- Python 3.9 or newer
- A current Codex release
- An existing local project to receive MEVA

MEVA is the source checkout. Your application is the target project. Keep them
as separate directories.

### 1. Get MEVA

Clone or download this repository, then open a terminal in the MEVA checkout.

### 2. Preview the installation

Replace the path below with the project where Codex should work:

```sh
TARGET_PROJECT=/path/to/my-project
./install.sh --preview "$TARGET_PROJECT"
```

The preview lists the files that would be added and does not change the target.

### 3. Install

```sh
./install.sh "$TARGET_PROJECT"
```

The installer checks the source and target before making changes, stages its
work, and rolls back if anything goes wrong. It will not silently overwrite an
existing project bootstrap or configuration file.

It adds:

- the MEVA bootstrap and Codex configuration;
- the five specialist role definitions;
- the durable project-state template;
- the checker, validation fixtures, and reviewer guidance; and
- an ownership manifest so removal can be safe later.

If the target already has `.meva/state.json`, MEVA preserves and validates it.
Otherwise, it creates the state from the template. Review the new state and
replace its project identity, goal, authority, budgets, and provenance before
doing substantive work.

Start a fresh Codex session after installation so it loads the project
bootstrap and role configuration.

## Remove MEVA

Preview removal first:

```sh
./uninstall.sh --preview "$TARGET_PROJECT"
```

Then remove the installation:

```sh
./uninstall.sh "$TARGET_PROJECT"
```

The uninstall script removes only files created by MEVA that are still
unchanged. It preserves your project files and keeps `.meva/state.json` for
recovery by default.

If MEVA created the state and you want to remove it too, use:

```sh
./uninstall.sh --purge-state "$TARGET_PROJECT"
```

Pre-existing or adopted state is always preserved. Changed files, malformed
manifests, and unsafe paths fail closed without mutation.

## Check your installation

From the MEVA checkout:

```sh
python3 tools/meva_check.py check-package --root .
python3 tools/meva_check.py validate-state .meva/state.json
```

The first command checks that the package is complete and internally
consistent. The second checks the active project state. A static pass confirms
the files and structure; live runtime activation is reported separately and is
honestly shown as `unverified` when the environment cannot attest to it.

## What MEVA protects

- One accountable owner for each piece of work
- Clear boundaries for what may be changed and who may change it
- Durable decisions and evidence instead of chat-only promises
- Independent validation and review when the work calls for them
- A fail-closed response when authority, safety, or evidence is unclear
- A lightweight local path for ordinary, reversible work

MEVA is a coordination and assurance layer, not a replacement for runtime
security, access control, approvals, or professional judgment. It also does
not provide frontend implementation roles; its current role library is aimed
at backend, AI, data, platform, and embodied-AI work.

## Learn more

- [`AGENTS.md`](AGENTS.md) — the project bootstrap and operating contract
- [`Agent.md`](Agent.md) — the complete behavior and role manual
- [`docs/meva-architecture.md`](docs/meva-architecture.md) — the design and
  rationale
- [`docs/reviewer-handbook.md`](docs/reviewer-handbook.md) — independent review
  guidance
- [`contracts/meva.schema.json`](contracts/meva.schema.json) — the machine-
  readable contract

MEVA is intentionally small at the surface and rigorous underneath: easy to
start, clear to inspect, and able to grow with the work.
