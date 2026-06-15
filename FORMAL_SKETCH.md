# Formal Sketch

Sentinel Guard is not a verified proof project. It is a small runtime
verification prototype designed so the policy language and monitor semantics
could later be formalized.

## Trace Model

A run is a finite trace of proposed tool calls and monitor decisions:

```text
tau = [e_1, e_2, ..., e_n]

e_i = {
  call: ToolCall,
  decision: Allow | Block(rule_id, reason),
  result: Artifact?   # present only when allowed
}
```

The monitor decides before execution:

```text
M(policy, tau_prefix, task_context, proposed_action) -> decision
```

Blocked actions do not execute and therefore produce no artifact.

## Action Model

Each action has:

```text
name
args
derived_from: set[artifact_id]
```

Each task type grants a least-privilege action set:

```text
allowed_tools(task_type) = {tool_1, ..., tool_k}
```

Task-scoped policy synthesis proposes a concrete `allowed_tools` set plus
argument restrictions, confirmation requirements, protected labels, and blocked
path/shell patterns. The synthesizer is not trusted as a proof; its output is
still checked by the deterministic monitor.

Policies may also include finite-trace temporal rules:

```text
temporal_rule = {
  id,
  before: action_name,
  require_events: set[action_name],
  require_confirmation: bool
}
```

These rules are intentionally small and deterministic. They are a bridge toward
a real temporal policy language rather than a full DSL.

## Artifacts And Provenance

Each artifact has:

```text
artifact_id
source_tool
labels subset {public, private, secret, untrusted}
parents subset artifact_id
```

The provenance relation is:

```text
parent(p, c)  iff artifact c was derived from artifact p
```

Effective labels propagate along provenance edges:

```text
effective_labels(a) =
  labels(a) union union(effective_labels(p) for parent(p, a))
```

For a proposed action:

```text
labels_seen(action) =
  union(effective_labels(a) for a in action.derived_from)
```

This is the toy information-flow core: a public-looking draft derived from
private notes still carries the private label.

## Core Invariants

### 1. No protected provenance to external sinks

```text
G(allowed(a) and external_sink(a)
  -> labels_seen(a) intersection {private, secret, untrusted} = empty)
```

Unless a future policy explicitly defines a declassification exception, private,
secret, or untrusted-derived artifacts cannot flow to external sinks.

### 2. Least privilege by task

```text
G(allowed(a)
  -> a.name in allowed_tools(task_context.task_type))
```

This prevents a narrow task such as summarization from expanding into unrelated
tools such as web requests or file deletion.

### 3. Sensitive actions require confirmation

```text
G(allowed(a) and requires_confirmation(a)
  -> task_context.user_confirmed = true)
```

The current implementation uses a boolean task-context field. A richer version
could model user approvals as first-class trace events.

### 4. History-sensitive actions require prior events

```text
G(allowed(send_email)
  -> previously_allowed(draft_to_user))
```

This is a finite-trace temporal invariant. It requires the monitor to inspect
the trace prefix, not just the current tool name.

For generic temporal rules:

```text
G(allowed(a) and temporal_rule(before = a.name)
  -> all(required_event in previous_allowed_events for required_event in require_events))
```

### 5. Argument restrictions

For command/path-scoped rules:

```text
G(allowed(a)
  -> args(a) match allow_patterns(a)
  and args(a) do not match deny_patterns(a))
```

This supports synthesized policies such as "Bash is allowed only for pytest/npm
test" and product guardrails such as blocking `.env` reads or destructive shell
commands.

## Eval Model

Each scenario records:

```text
scenario_id
category
expected_allowed_tools
expected_blocked_tools
utility_relevant
security_relevant
```

The eval report computes utility preservation, unsafe-action blocking,
overblocking, underblocking, and rule trigger counts. This is not a proof of
security, but it makes the monitor behavior testable and auditable.

## Path Toward Formalization

The current YAML policy could be replaced by a small DSL with explicit syntax
for effects, labels, task capabilities, argument predicates, and temporal trace
rules. The invariants above map naturally to finite-trace temporal logic such as
LTLf.

A future Lean-backed version could define traces, provenance graphs, label
propagation, action semantics, and monitor checks, then prove a soundness
statement of the form:

```text
If every event in tau is allowed by M,
then no artifact with protected provenance reaches an external sink,
no sensitive action occurs without required confirmation,
every history-gated action has its required prior event,
and every action belongs to the task-scoped allowed tool set.
```

This repository does not include that proof. It is the applied prototype that
makes the boundary, provenance model, and invariants concrete.
