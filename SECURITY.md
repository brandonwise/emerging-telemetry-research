# Security Architecture and Operating Requirements

## Security objective

The system must remain safe even when every monitored source contains malicious instructions specifically designed to manipulate an AI agent.

Prompt-injection detection is useful telemetry, but it is not the primary safety control. Safety comes from architectural constraints that make injected instructions incapable of gaining privileges.

## Security invariants

- External content is never trusted as instructions.
- Agent authority is based on role, not model intelligence.
- Raw content and secrets never coexist in one execution context.
- Research authority and publishing authority are separated.
- Durable state is written only through narrow policy-enforced APIs.
- Unknown tool parameters, JSON fields, URLs, and destinations fail closed.
- Privileged credentials are scoped, rotated, and never exposed to research agents.
- Model responses are untrusted until validated.
- All security-relevant decisions are auditable.

## Agent permission matrix

| Role | Internet | Raw artifacts | Sanitized evidence | DB write | Shell | Secrets | Discord/email | Schedule/admin |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| Connector worker | Allowlisted | Write | No | Narrow | No | Source only | No | No |
| Sanitizer | No direct | Read | Write | Narrow | Sandboxed parser only | No | No | No |
| Extractor | No | No | Read bounded | Submit observation | No | Model credential via gateway | No | No |
| Specialist analyst | Optional allowlisted search through gateway | No | Read | Submit analysis | No | No | No | No |
| Skeptic | No or narrow search | No | Read | Submit review | No | No | No | No |
| Citation verifier | No | No | Read | Submit verification | No | No | No | No |
| Coordinator | No | No | Read | Submit final assessment | No | No | No | No |
| Renderer | No | No | Read report JSON | Write render record | No | Template access | No | No |
| Delivery adapter | No research | No | Read rendered output | Delivery status | No | Destination only | Yes | No |
| Operator/admin | Controlled | Controlled | Controlled | Controlled | Controlled | Break-glass | Controlled | Controlled |

## Content-security gateway

### Fetch controls

- Scheme allowlist: HTTPS by default; HTTP only per approved source
- Resolve hostname before request and after every redirect
- Reject prohibited IP ranges and mixed-address ambiguity
- Set maximum redirect count
- Strip or deny credentials in URLs
- Set DNS, connect, read, total, and idle timeouts
- Set maximum compressed and decompressed bytes
- Set content-type and file-extension allowlists
- Reject unexpected executable MIME types
- Use per-domain rate limits and concurrency limits
- Use a dedicated egress identity with no route to internal networks

### Parsing controls

- Perform parsing in a disposable sandbox
- Disable macros, JavaScript, plugins, external resource loading, and embedded file execution
- Limit archive depth, member count, path length, and expansion ratio
- Reject path traversal and device files
- Canonicalize line endings and Unicode
- Identify zero-width, bidirectional, confusable, or hidden content
- Strip active HTML and CSS
- Store only bounded excerpts for model consumption
- Treat OCR and image text as equally untrusted

### Malware and exploit-content controls

- Hash every artifact before processing
- Integrate malware scanning and YARA rules
- Quarantine suspicious binaries and documents
- Do not detonate or execute malware in the initial system
- Do not install monitored packages
- Do not compile or run proof-of-concept code
- Do not visit command-and-control endpoints from the production environment
- Add a separate approved malware-analysis environment only under a future threat model

## Prompt-injection resilience

### Input representation

Model inputs must clearly separate fixed instructions from untrusted data. Use a schema such as:

```json
{
  "task": "extract_security_observations",
  "policy_version": "2026-07-01",
  "untrusted_evidence": [
    {
      "evidence_id": "ev_...",
      "source_role": "researcher_observation",
      "text": "...bounded sanitized text..."
    }
  ],
  "allowed_output_schema": "observation.v1"
}
```

The model must not receive browser-rendered page state, hidden content, tool descriptions unrelated to the task, secret-bearing environment variables, or prior untrusted conversational memory.

### Output handling

- Parse JSON strictly; do not accept markdown fences or trailing prose
- Enforce enums, lengths, references, and numeric ranges
- Reject unknown fields
- Never execute strings supplied in model output
- Map approved semantic actions to fixed server-side implementations
- Revalidate every referenced evidence ID and URL
- Use deterministic claim/citation validation
- Log parse and policy failures without exposing secrets

### Cross-agent communication

- Agents exchange object IDs and schema-valid objects only
- No free-form “instructions to the next agent” field
- No agent may delegate a tool permission it does not possess
- No source content enters agent names, tool names, schedule expressions, or capability definitions
- Session context is disposable and bounded

### Delayed and persistent attacks

- Never copy source text into long-term agent memory
- Never generate scheduled tasks from a source artifact
- Never treat a prior model message as authoritative configuration
- Store extracted facts with provenance, not conversational summaries
- Re-run sanitizer and extractor when versions change
- Expire watch hypotheses unless refreshed by evidence
- Track canary tokens and forbidden-secret patterns across outputs

## Secret management

- Store credentials in a managed secret store or protected deployment environment
- Use one credential per connector/destination where possible
- Use short-lived tokens and workload identity where available
- Restrict GitHub, Discord, email, object-store, database, and model credentials independently
- Never make secrets available in container images, repository files, test fixtures, logs, traces, reports, or model prompts
- Scrub authorization headers, query parameters, cookies, and signed URLs from telemetry
- Rotate a connector credential after any suspected source-content escape

## GitHub and CI security

- Private repository from initial creation
- Protected main branch and required reviews
- CODEOWNERS on policies, workflows, schemas, prompts, infra, and security code
- GitHub Actions pinned to immutable commit SHAs
- Minimal `permissions:` in each workflow
- No untrusted fork code with production secrets
- No dynamic `curl | sh`
- Generate and retain SBOM and dependency lockfiles
- Scan source, containers, IaC, and secrets
- Review dependency licenses and source-client terms
- Use artifact attestations and immutable release references where supported

## Logging and audit

Record:

- Authentication and authorization decision
- Tool invocation and policy decision
- Source fetch metadata and redirects
- Sanitizer detections and disposition
- Model ID, prompt/template version, token use, and output hash
- Workflow transitions and retries
- Evidence read and report claim mapping
- Delivery target identifier and receipt, without message secrets
- Operator approvals and configuration changes

Audit logs must be append-only or forwarded to a system where the application cannot rewrite history.

## Portal boundary

- The portal is read-only and has no collection, workflow mutation, threshold, feedback, or
  delivery routes.
- Loopback is the default bind posture.
- Private-LAN mode requires a strong access token and accepts only configured private source
  networks.
- Sessions use signed, expiring, HttpOnly, SameSite=Strict cookies; secure cookies activate with
  TLS.
- The application does not trust forwarded client headers.
- Browser assets are local and Content Security Policy blocks scripts and third-party resources.
- CSV exports escape spreadsheet formula prefixes.
- LAN mode must not be publicly port-forwarded; use TLS or an encrypted overlay for untrusted
  network segments.

## Security testing

Required test classes:

- SSRF and DNS rebinding
- Redirect policy bypass
- Archive bomb and parser resource exhaustion
- MIME confusion and polyglot files
- Hidden/encoded prompt injection
- Tool-call and JSON schema smuggling
- Secret exfiltration canaries
- Cross-agent privilege escalation
- Repost/sybil corroboration manipulation
- Source credential compromise
- Compromised model/provider behavior
- CI dependency and action compromise
- Report HTML injection and unsafe link handling

## Incident response priorities

1. Disable affected connector or agent route.
2. Revoke and rotate scoped credentials.
3. Preserve run, artifact, policy, model, and delivery records.
4. Stop publication if evidence integrity is uncertain.
5. Identify all outputs derived from affected evidence or component version.
6. Issue a correction with explicit lineage.
7. Add the attack to the regression suite.
8. Review whether the architecture, not just the detector, must change.
