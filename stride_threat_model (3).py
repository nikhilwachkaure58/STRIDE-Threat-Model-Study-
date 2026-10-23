#!/usr/bin/env python3
"""
STRIDE Threat Model Study
Generate a structured threat-model inventory for microservice data flows.

This is an educational threat-modeling helper. It does not scan systems or prove
that a system is secure. Validate the model with service owners and security staff.
"""
from __future__ import annotations
import argparse
import csv
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List

STRIDE = {
    "S": "Spoofing",
    "T": "Tampering",
    "R": "Repudiation",
    "I": "Information Disclosure",
    "D": "Denial of Service",
    "E": "Elevation of Privilege",
}

@dataclass
class Threat:
    threat_id: str
    component_or_flow: str
    data_flow: str
    stride_category: str
    threat_scenario: str
    security_property: str
    existing_controls: str
    recommended_mitigations: str
    likelihood: int
    impact: int
    owner: str
    status: str = "Open"

    @property
    def risk_score(self) -> int:
        return self.likelihood * self.impact

    @property
    def risk_rating(self) -> str:
        score = self.risk_score
        if score >= 20:
            return "Critical"
        if score >= 15:
            return "High"
        if score >= 8:
            return "Moderate"
        return "Low"

def starter_threats() -> List[Threat]:
    return [
        Threat("STRIDE-001", "API Gateway → Identity Service", "HTTPS request / access token",
               "Spoofing", "A caller presents a stolen or forged token to impersonate a legitimate client.",
               "Authentication", "TLS; token validation at gateway (assumed)",
               "Validate issuer, audience, expiry, signature, and key rotation; use short-lived tokens and workload identity.",
               3, 5, "Identity Platform"),
        Threat("STRIDE-002", "Order Service → Payment Service", "Payment authorization request",
               "Tampering", "A request field is altered in transit or by a compromised service, changing amount or destination.",
               "Integrity", "TLS between services (assumed)",
               "Use authenticated service-to-service channels, schema validation, signed or integrity-protected messages, and server-side amount calculation.",
               3, 5, "Payments Team"),
        Threat("STRIDE-003", "Order Service → Audit Log", "Order state-change event",
               "Repudiation", "A privileged actor changes order state and disputes the action because logs are incomplete or mutable.",
               "Accountability", "Application logs (assumed)",
               "Record actor/service identity, correlation ID, timestamp, and outcome; ship logs to append-only storage and monitor access.",
               3, 4, "Platform Engineering"),
        Threat("STRIDE-004", "Customer API → Customer Database", "Customer profile query / response",
               "Information Disclosure", "A broken authorization check exposes another customer's personal data.",
               "Confidentiality", "Database network policy (assumed)",
               "Enforce object-level authorization, least-privilege database roles, data minimization, encryption, and access auditing.",
               3, 5, "Customer Platform"),
        Threat("STRIDE-005", "Public API → Search Service", "Search query",
               "Denial of Service", "Expensive or unbounded queries exhaust CPU, memory, or downstream capacity.",
               "Availability", "Basic ingress limits (assumed)",
               "Apply rate limits, query complexity limits, timeouts, quotas, caching, circuit breakers, and load testing.",
               4, 4, "API Platform"),
        Threat("STRIDE-006", "Worker → Admin API", "Administrative command",
               "Elevation of Privilege", "A worker identity with excessive permissions invokes administrative operations.",
               "Authorization", "Service account (assumed)",
               "Use least-privilege workload identities, separate admin interfaces, explicit authorization policies, and periodic permission reviews.",
               3, 5, "Cloud Security"),
        Threat("STRIDE-007", "Message Broker → Inventory Service", "Inventory update event",
               "Tampering", "An untrusted producer publishes forged or replayed inventory events.",
               "Integrity", "Broker authentication (assumed)",
               "Authorize producers per topic, validate message schema, use idempotency/replay controls, and monitor anomalous producers.",
               3, 4, "Inventory Team"),
        Threat("STRIDE-008", "Microservice → Secrets Store", "Secret retrieval request",
               "Information Disclosure", "A compromised service retrieves credentials beyond its required scope.",
               "Confidentiality", "Central secrets manager (assumed)",
               "Scope secrets by workload, rotate automatically, audit reads, block static secrets in source control, and use short-lived credentials.",
               3, 5, "Secrets Management"),
        Threat("STRIDE-009", "Service Mesh / Internal Network", "East-west service traffic",
               "Spoofing", "An unauthorized workload impersonates a trusted service on the internal network.",
               "Authentication", "Internal network segmentation (assumed)",
               "Use mutual TLS, workload identity, certificate rotation, and policy enforcement for service-to-service communication.",
               3, 4, "Network Security"),
        Threat("STRIDE-010", "Event Consumer → Data Store", "Asynchronous event processing",
               "Denial of Service", "A message backlog or poison-message loop delays processing and degrades service availability.",
               "Availability", "Basic queue monitoring (assumed)",
               "Set queue limits, dead-letter queues, retry budgets, back-pressure, consumer scaling, and alert thresholds.",
               3, 4, "Reliability Engineering"),
    ]

def write_register(threats: List[Threat], output: Path) -> None:
    fields = ["threat_id", "component_or_flow", "data_flow", "stride_category",
              "threat_scenario", "security_property", "existing_controls",
              "recommended_mitigations", "likelihood", "impact", "risk_score",
              "risk_rating", "owner", "status"]
    with output.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        for threat in threats:
            row = asdict(threat)
            row["risk_score"] = threat.risk_score
            row["risk_rating"] = threat.risk_rating
            writer.writerow(row)

def recalculate(input_path: Path, output_path: Path) -> int:
    with input_path.open("r", newline="", encoding="utf-8-sig") as f:
        rows = list(csv.DictReader(f))
    if not rows:
        raise SystemExit("Input CSV has no threat rows.")
    fields = list(rows[0].keys())
    for field in ("risk_score", "risk_rating"):
        if field not in fields:
            fields.append(field)
    for row in rows:
        try:
            likelihood, impact = int(row["likelihood"]), int(row["impact"])
            if not (1 <= likelihood <= 5 and 1 <= impact <= 5):
                raise ValueError
        except (KeyError, ValueError):
            raise SystemExit("Each row must contain likelihood and impact integers from 1 to 5.")
        score = likelihood * impact
        row["risk_score"] = score
        row["risk_rating"] = "Critical" if score >= 20 else "High" if score >= 15 else "Moderate" if score >= 8 else "Low"
    with output_path.open("w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(f, fieldnames=fields)
        writer.writeheader()
        writer.writerows(rows)
    return len(rows)

def main() -> None:
    parser = argparse.ArgumentParser(description="Create or rescore a STRIDE microservice threat register.")
    parser.add_argument("--output", default="stride_threat_register.csv", help="Output CSV path")
    parser.add_argument("--input", help="Optional existing CSV to recalculate scores")
    args = parser.parse_args()
    output = Path(args.output)
    if args.input:
        count = recalculate(Path(args.input), output)
        print(f"Recalculated {count} threat(s) -> {output.resolve()}")
    else:
        threats = starter_threats()
        write_register(threats, output)
        print(f"Created {len(threats)} illustrative STRIDE threats -> {output.resolve()}")
        print("Review all assumed controls, ratings, owners, and mitigations with system stakeholders.")

if __name__ == "__main__":
    main()
