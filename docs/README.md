# ClawNet

ClawNet is an AI-powered terminal security monitoring tool enhanced with OpenClaw intelligence for real-time threat analysis, contextual risk scoring, and autonomous response.

It monitors active network connections, validates processes, detects suspicious behavior, explains threats in context, and helps users take action before incidents happen.

---

## Features

- Live TCP/UDP connection monitoring
- Real-time process tracking
- GeoIP lookup for remote IPs
- VPN status detection
- Process path validation
- New connection alerts
- Automatic risk scoring
- OpenClaw-powered threat analysis
- Natural language security explanations
- AI-powered remediation suggestions
- Suspicious process detection
- Autonomous response engine
- Kill process / block IP recommendations

---

## Tech Stack

### Core Monitoring
- Python
- psutil
- socket
- scapy

### AI Layer
- OpenClaw

### Backend
- FastAPI

### Database
- PostgreSQL
- Redis

### Future Dashboard
- Next.js

---

## Installation

### Clone Repository

```bash
git clone https://github.com/rajarshidattapy/clawnet.git
cd clawnet
````

---

## Setup Virtual Environment

```bash
python -m venv venv
source venv/bin/activate

# Windows
venv\Scripts\activate
```

---

## Install Dependencies

```bash
pip install -r requirements.txt
```

---

## Environment Variables

Create a `.env` file:

```env
OPENAI_API_KEY=your_key_here
OPENCLAW_API_KEY=your_key_here
DATABASE_URL=your_postgres_url
REDIS_URL=your_redis_url
```

---

## Run ClawNet

```bash
python main.py
```

or

```bash
uvicorn app.main:app --reload
```

---

## Example Flow

```text
Unknown process opens outbound connection
        ↓
ClawNet detects it
        ↓
OpenClaw analyzes the threat
        ↓
Risk score increases
        ↓
Suggested action:
Kill process + block IP
```

---

## Project Structure

```bash
clawnet/
│
├── app/
│   ├── monitor/
│   ├── risk_engine/
│   ├── ai_analysis/
│   ├── alerts/
│   ├── api/
│   └── main.py
│
├── requirements.txt
├── .env.example
└── README.md
```

---

## Vision

ClawNet turns passive monitoring into intelligent security.

Not just:

“What is happening?”

but

“Is this dangerous, and what should I do?”

```
```
