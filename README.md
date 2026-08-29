# MySmartMed Secure Research Prototype

MySmartMed is a local-first medication-adherence prototype for evaluating encrypted caregiver-managed records, scheduled-dose workflows, refill alerts, and clinician-facing summaries. It is designed for research demonstrations with synthetic data.

## Security properties implemented

- AES-256-GCM authenticated field encryption with a fresh nonce for every encrypted value.
- PBKDF2-HMAC-SHA256 credential derivation with domain separation between password verification and encryption keys.
- Server-side, session-scoped encryption-key storage; keys are discarded on logout.
- CSRF validation on every state-changing request, secure cookie defaults, and session rotation at login.
- Ownership checks for every patient, medicine, refill, visit, report, and notification operation.
- Per-user reminder queues; one caregiver cannot consume another caregiver's notifications.
- Database-enforced uniqueness for a medicine dose at a scheduled timestamp.
- Encrypted clinical notes, refill quantities, thresholds, dates, contact details, and compliance status.

## Run locally

Create a virtual environment, install dependencies, set a strong local secret, then run the application:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
$env:MYSMARTMED_SECRET_KEY = "use-a-long-random-secret-here"
python app.py
```

Open `http://127.0.0.1:5000`. The application creates `mysmartmed.db` on first run. Do not use real patient data for a classroom or paper demonstration.

## Tests

```powershell
python -m unittest discover -s tests -v
```

## Research evaluation guidance

Report functional test results, encryption/decryption and PDF-generation latency, database/storage overhead, reminder-delivery correctness, and usability feedback from an ethically approved study if human participants are used. Adherence is calculated from expected schedule occurrences, not only from recorded logs; unconfirmed expected doses are reported separately.

## Scope and limitations

This is not a medical device, EHR, clinical decision-support tool, or a production deployment. It does not validate prescriptions, recommend medication, detect drug interactions, send remote push notifications, provide multi-factor authentication, or satisfy HIPAA/DPDP/GDPR compliance by itself. Browser reminders require the local application and an authenticated caregiver session to be running.
