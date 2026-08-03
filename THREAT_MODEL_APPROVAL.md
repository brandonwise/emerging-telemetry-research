# Deployment approval template

Status: not approved

This repository does not grant collection, scheduling, external delivery, or autonomous mutation
authority. Deployment approvals are local, expiring, and bound to the exact code, policy, source,
terms, and discovery configuration reviewed by an operator.

Create a private deployment request after onboarding:

```bash
emerging-telemetry-research setup approval-request
```

Review the generated request and current threat model. An authorized operator can then create the
local approval record:

```bash
emerging-telemetry-research setup approval-apply \
  .emerging-telemetry-research/deployment-approval-request.json \
  --approved-by NAME \
  --approval-id TICKET-OR-REVIEW-ID
```

The approval file lives under `.emerging-telemetry-research/`, is ignored by Git, expires, enumerates approved
sources and capabilities, and becomes invalid whenever a protected input changes. Copying or
forking this repository therefore never copies production authority.
