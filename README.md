# Aegis AI

Aegis AI is a local FastAPI demo for viewing simulated network events, alerts, and block actions. The simulator uses caller-selected event labels and randomized illustrative scores. **The XGBoost artifact is loaded for display only; it is not connected to live detection, and the project does not publish a verified accuracy metric.** Do not use the current demo as a production intrusion detection or prevention system.

## Requirements

- Python 3.10 or newer
- Windows for the optional Windows Firewall rule commands
- The pinned Python packages in `requirements.txt`

## Setup

From the repository root, create and activate a virtual environment, then install dependencies:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
```

Start the API:

```powershell
python app.py
```

The API listens at `http://127.0.0.1:8000`. OpenAPI docs are at `http://127.0.0.1:8000/docs`; `/api/model-info` describes the model artifact and explicitly reports that inference is disabled.

## Email alerts (optional)

Email delivery is disabled unless all three environment variables are set: `AEGIS_EMAIL_SENDER`, `AEGIS_EMAIL_RECEIVER`, and `AEGIS_EMAIL_PASSWORD`. Use a newly issued app password stored in your local environment; never commit it or put it in a README. A credential was previously committed to this repository's history, so revoke it with the email provider before configuring a replacement. Removing it from the current source does not erase old commits.

## Demo behavior and limitations

- `POST /api/simulate` accepts an event label supplied by the caller. It does not infer an attack from packet features.
- Displayed scores are randomized demo values, not calibrated probabilities or model confidence.
- Block actions use Windows Firewall commands and may fail without Windows and administrator permissions. Other operating systems do not receive firewall protection.
- The XGBoost pickle files and SQLite database are local project artifacts. Do not load untrusted pickle files.
- This project has no verified model evaluation, deployment hardening, authentication, or production monitoring.
