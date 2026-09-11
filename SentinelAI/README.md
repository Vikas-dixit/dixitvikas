# SentinelAI 🛡️

SentinelAI is a lightweight personal SOC (Security Operations Center) for students, home labs, and small teams. It ingests security events, scores risk, explains why an event is suspicious, and exposes a simple API for a dashboard or future AI assistant.

## What it does

- Detects repeated failed-login attempts
- Flags suspicious ports and processes
- Scores each event from 0–100
- Returns a human-readable explanation
- Provides a FastAPI backend
- Includes sample events for instant testing
- Docker-ready

## Architecture

```text
Event source -> FastAPI -> Detection Engine -> Risk Scoring -> Alert Response
                               |
                               +-> Rules (login, port, process, network)
```

## Quick start

```bash
cd SentinelAI
python -m venv .venv
# Windows
.venv\Scripts\activate
# Linux/macOS
source .venv/bin/activate

pip install -r requirements.txt
uvicorn app.main:app --reload
```

Open `http://127.0.0.1:8000/docs`.

## Example request

```json
{
  "event_type": "login",
  "source_ip": "192.168.1.23",
  "username": "admin",
  "success": false,
  "failed_attempts": 9,
  "destination_port": 22,
  "process_name": "ssh"
}
```

## Example response

```json
{
  "severity": "high",
  "risk_score": 85,
  "reasons": [
    "Repeated failed logins may indicate brute-force activity",
    "SSH is a sensitive remote-access service"
  ]
}
```

## Roadmap

- [ ] Live Windows/Linux log ingestion
- [ ] SQLite/PostgreSQL event storage
- [ ] Web dashboard
- [ ] ML anomaly-detection model
- [ ] Threat-intelligence enrichment
- [ ] AI incident explanations
- [ ] Email/Discord alerts
- [ ] Docker Compose deployment

## Ethics

SentinelAI is defensive software. Use it only on systems and networks you own or are explicitly authorized to monitor.
