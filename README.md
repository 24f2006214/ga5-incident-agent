# GA5 Observable Incident Triage agent

Standard-library Python service (no dependencies) implementing:

- `POST /v2/incidents` – one LLM planning call → diagnosis + parallel diagnostic dispatches
- `POST /v2/incidents/{runId}/receipts` – receipt-driven state machine (503 retry once, timeout suppression,
  approval gate for `rollback_deployment` / `disable_feature`, scaling-limit → page owner)
- `GET /v2/incidents/{runId}` – stored state
- Idempotent replays, 409 on changed content, 400/422 on invalid input, OTLP trace with W3C context continuation,
  redaction of every `sensitive` value.

## Run locally

```bash
LLM_API_KEY=... python app.py            # real model
MOCK_LLM=1 PORT=8765 python app.py       # mock planner
python test_local.py                     # simulated grader (against BASE, default http://127.0.0.1:8765)
```

## Env vars

| var | default |
|---|---|
| `LLM_API_KEY` | – (AI Pipe token / OpenAI key / Gemini key) |
| `LLM_BASE_URL` | `https://aipipe.org/openai/v1` |
| `LLM_MODEL` | `gpt-4.1-mini` |
