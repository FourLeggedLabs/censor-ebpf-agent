# Censor Agent HTTP API

Schemas: `censor.agent.v1` in [FourLeggedLabs/protos](https://github.com/FourLeggedLabs/protos) (protojson on the wire).

## Auth

`Authorization: Bearer <key>` from `/etc/censor/api-key`.

## `GET /v1/agent/policy`

Query: `repo_owner`, `repo_name`, `workflow`, `workflow_ref`, `run_id`, `run_attempt`, `job`, `job_id`, `sha`, `ref`, `actor`, `event_name`, `runner_arch`, `runner_os`, `matrix`, `agent_version`.

Response: `AgentPolicy`.

## `POST /v1/agent/logs`

Multipart:
- `metadata` — protojson `AgentLogUpload`
- `log` — `agent.ndjson.gz` (gzip of NDJSON `AgentEvent` lines)
