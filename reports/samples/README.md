# Frozen sample report

`frozen-flash/` is generated from `tests/fixtures/vertical_slice/flash-manifest.json`. It includes
the immutable content-addressed inputs, verified report JSON, self-contained HTML, and hash-chained
audit log.

Regenerate in a clean output directory:

```bash
uv run threat-radar fixture run \
  tests/fixtures/vertical_slice/flash-manifest.json \
  --output reports/samples/frozen-flash \
  --json
```

Expected report properties:

- publication class: `flash`
- priority score: `90.5`
- degraded source: `cve-list-v5`
- report ID: `rp_0e7aa38d9fe231421703d76d`
- rendered HTML SHA-256: `2628cfd75d8539f6bed3705171f55de5f112b428b71a3d86ae956d19aaf7c350`

External delivery remains disabled.
