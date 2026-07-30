# Extending Threat Radar

## Add a source surface

1. Give the surface a stable `source_id`. Do not reuse a provider name.
2. Add its query or adapter configuration to `config/discovery.yaml`.
3. Add approval, retention, rate limits, and the adapter to `config/sources.yaml` and
   `config/source-terms.yaml`.
4. Fetch only through the centralized safe-fetch boundary.
5. Map the result to `DiscoverySignal` with `source_id`, `source_type`, URL, timestamps, and a
   bounded summary.
6. Add parser, attribution, failure, and hostile-content tests.
7. Run a live `plan` collection and `make eval-coverage`.

A search provider and a source surface are different concepts. One Brave account can retrieve a
GitHub result and a TikTok result; telemetry must still record `github-security-web` and
`tiktok-security`.

## Add a direct platform API

Keep direct integrations optional. Require their credentials only when the adapter is enabled.
Document current platform approval, authentication, rate limits, retention, deletion, and
attribution rules. Never fall back to scraping when an API denies access.

## Add an agent provider

Implement the `AgentProvider` protocol in `packages/agents/runtime.py`:

```python
class AgentProvider(Protocol):
    async def invoke(self, invocation: AgentInvocation) -> AgentProviderResult: ...
```

The adapter must:

- accept only the sanitized packet and prior typed assessments;
- disable tools, browsing, memory, and session persistence;
- return one assessment object;
- capture provider, model, input/output tokens, estimated cost, and duration;
- enforce timeouts and response-size limits;
- let local schema validation reject unknown fields or evidence IDs.

Register the adapter in `AGENT_ADAPTERS`, expose only secret names in `.env.example`, add mocked
transport tests, and run the real-provider eval before documenting support.

## Add an agent role

Changing the graph is a contract change:

1. Define the role prompt and exact dependencies.
2. Update the planner graph and assessment schema if needed.
3. Decide whether the role is advisory or may supply bounded narrative.
4. Update role completion math and expected assessment counts.
5. Add failure tests proving downstream dispatch stops.
6. Update both architecture diagrams.

No role may own durable state, scoring, source access, delivery, or publication.

## Add a platform package

Place a template under `integrations/templates/<platform>/`, add its name to
`SUPPORTED_PLATFORMS`, and test generation into an empty directory. A platform package should call
the CLI and explain secrets, scheduling, evals, and rollback. It should not fork the core pipeline.

## Definition of done

An extension is complete when:

- config and schema validation pass;
- unit, hostile-content, and failure tests pass;
- deterministic acceptance is unchanged;
- agent/source evals include the new path;
- cost and latency are attributed;
- setup, operations, rollback, and platform notes are current;
- diagrams match the running system;
- a clean checkout can follow the documented Make workflow.
