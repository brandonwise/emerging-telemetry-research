# Perplexity adapter

Perplexity plugs into the provider-neutral agent boundary. Collection, evidence storage, scoring,
verification, and publishing still run locally.

1. Copy `radar.env.example` to `radar.env`.
2. Set `BRAVE_API_KEY` and `XAI_API_KEY` for discovery.
3. Set the agent variables:

   ```dotenv
   RADAR_AGENT_MODE=shadow
   RADAR_AGENT_ADAPTER=openai-compatible
   RADAR_AGENT_PROVIDER_NAME=perplexity
   RADAR_AGENT_BASE_URL=https://api.perplexity.ai
   RADAR_AGENT_MODEL=your-approved-perplexity-model
   RADAR_AGENT_API_KEY=your-key-from-a-secret-store
   ```

4. Run `./run-radar.sh`.
5. Inspect `agent_reviews` and usage in the generated report before choosing `active` mode.

The adapter sends only sanitized evidence packets and prior typed assessments. Perplexity does not
receive collection credentials, raw artifacts, delivery credentials, workflow state, or
publication authority. If the selected endpoint does not support strict JSON Schema output, place
a small compatibility proxy in front of it or use one of the command adapters.
