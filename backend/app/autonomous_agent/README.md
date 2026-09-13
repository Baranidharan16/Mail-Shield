# MailShield — Autonomous AI Agent Architecture (Foundation)

## Current Status: `AUTONOMOUS AGENT: ○ NOT CONFIGURED`

This directory provides a dedicated, clean architectural placeholder for the future Autonomous AI Agent layer in **MAILSHIELD**.

> [!IMPORTANT]
> **Safety & Integrity Notice**:
> - The Autonomous AI Agent is **NOT** enabled in this release.
> - **NO** real-world autonomous actions (such as email deletion, firewall IP blocking, domain sinkholing, or user account modification) are performed.
> - The existing manual email upload, Keras ML model, Keras NLP model, forensic engine, deterministic risk scoring, and Gemini/Sarvam assistant continue to operate normally without interference.

---

## Architecture Blueprint (Future Expansion)

```
                       AUTHENTICATED USER
                                │
                                ▼
                       EMAIL UPLOAD / ARRIVAL
                                │
                                ▼
                  MAILSHIELD FORENSIC PIPELINE
        ┌───────────────────────┼───────────────────────┐
        ▼                       ▼                       ▼
    ML ENGINE              NLP ENGINE            FORENSIC ENGINE
  (mailshield_ml)       (mailshield_nlp)         (Headers/Auth/URLs)
        │                       │                       │
        └───────────────────────┼───────────────────────┘
                                ▼
                       RISK SCORING ENGINE
                                │
                                ▼
                     MAILSHIELD AI REASONING
                    (Gemini / Future Ollama)
                                │
                                ▼
                       USER INVESTIGATION
                      (Persistent Database)
                                │
                                ▼
               ===================================
               FUTURE EXTENSION: AUTONOMOUS AGENT
               ===================================
                                │
                ┌───────────────┴───────────────┐
                ▼                               ▼
        ACTION PLANNER                    ORCHESTRATOR
                │                               │
                ▼                               ▼
       HUMAN-IN-THE-LOOP APPROVAL        AUDITED WORKFLOW
```

---

## Directory Structure

```
autonomous_agent/
│
├── __init__.py           # Subsystem status ("NOT CONFIGURED")
├── agent.py              # Abstract AutonomousAgent base interface
├── orchestrator.py       # Workflow orchestrator placeholder
├── tools/                # Registered security tooling
│   └── __init__.py
├── workflows/            # Execution workflows
│   ├── __init__.py
│   └── email_monitor.py  # Future autonomous mailbox listener (inactive)
├── memory/               # Episodic and knowledge memory
│   └── __init__.py
└── README.md             # This document
```

---

## Abstract Interface

```python
class AutonomousAgent(abc.ABC):
    @abc.abstractmethod
    async def analyze(self, investigation: Any) -> Dict[str, Any]:
        pass

    @abc.abstractmethod
    async def plan_actions(self, investigation: Any) -> List[Dict[str, Any]]:
        pass

    @abc.abstractmethod
    async def execute_action(self, action: Dict[str, Any]) -> Dict[str, Any]:
        pass
```
