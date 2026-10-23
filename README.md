# STRIDE-Threat-Model-Study-
STRIDE Threat Model Study: Mapped Microservice Data Flows and Structural Threats Using OWASP Threat Dragon Domain: Application Security Approach
# STRIDE Threat Model Study

**Project title:** STRIDE Threat Model Study: Mapped microservice data flows and structural threats using OWASP Threat Dragon.

This educational project provides a Python command-line helper that creates a structured threat register for representative microservice data flows. It maps scenarios to the six STRIDE categories and records security properties, assumed existing controls, recommended mitigations, likelihood, impact, risk score, owner, and status.

> **Important:** The sample is an illustrative starting point, not a completed assessment of your actual architecture. Confirm data flows, trust boundaries, control evidence, and ratings with system owners and security reviewers. The script does not scan a network or establish that a system is secure.

## Files

- `stride_threat_model.py` — threat-register generator and score recalculator.
- `requirements.txt` — Python runtime/dependency note.
- `requirements.pdf` — printable software and project requirements.
- `project_report.pdf` — project report featuring the supplied university logo.
- `stride_threat_register.csv` — sample register containing 10 illustrative threats.
- `university_logo.png` — supplied logo included in the report.

## Requirements

- Python 3.10 or newer recommended.
- No third-party Python packages are required.
- OWASP Threat Dragon is recommended for visual data-flow diagrams and collaborative threat-model review.
- A spreadsheet application is optional for reviewing the generated CSV.

## Generate the starter threat register

```bash
python stride_threat_model.py
```

Creates `stride_threat_register.csv` in the current directory.

Choose a custom output path:

```bash
python stride_threat_model.py --output reports/my_stride_register.csv
```

The output directory must already exist.

## Recalculate risk scores

Edit `likelihood` and `impact` in the CSV with values from 1 to 5, then run:

```bash
python stride_threat_model.py --input stride_threat_register.csv --output scored_register.csv
```

Risk score = likelihood × impact. The sample bands are:

| Score | Example rating |
|---:|---|
| 20–25 | Critical |
| 15–19 | High |
| 8–14 | Moderate |
| 1–7 | Low |

These are example thresholds, not universal standards. Align them with your organization’s approved risk matrix.

## STRIDE categories

- **Spoofing:** impersonating a user, service, or workload.
- **Tampering:** unauthorized modification of data or messages.
- **Repudiation:** inability to reliably attribute actions.
- **Information Disclosure:** unauthorized access to confidential information.
- **Denial of Service:** reducing availability or exhausting resources.
- **Elevation of Privilege:** gaining permissions beyond those intended.

## Using OWASP Threat Dragon

1. Create a threat model for the target application or microservice system.
2. Draw processes/services, data stores, external entities, data flows, and trust boundaries.
3. Label protocols, authentication, sensitive data, and relevant trust transitions.
4. Use the STRIDE categories to brainstorm threats for each component and flow.
5. Record evidence-backed controls and actionable mitigations.
6. Review the model with developers, platform owners, security, and operations.
7. Export or document the approved model and track mitigation owners to closure.

Threat Dragon UI and export options can vary by version. Consult the official OWASP Threat Dragon documentation for current instructions.

## Security and quality notes

- Existing controls in the sample are explicitly marked “assumed”; verify them before treating them as implemented.
- Threat-model completeness depends on accurate diagrams and trust boundaries.
- Risk scores are prioritization aids, not precise probability estimates.
- Avoid putting sensitive architecture details, credentials, or confidential vulnerabilities in a public GitHub repository.
- Review and update the model after major architectural changes and security incidents.

## References

- OWASP Threat Dragon: https://owasp.org/www-project-threat-dragon/
- OWASP Threat Modeling: https://owasp.org/www-community/Threat_Modeling
