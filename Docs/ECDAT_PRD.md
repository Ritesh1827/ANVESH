# Product Requirements Document (PRD)

## ECDAT — Enterprise Cryptographic Discovery & Analysis Tool
*Post-quantum cryptography readiness: discovery, risk, and migration intelligence*

**Document version:** 1.0
**Status:** Final architecture frozen for prototype build

---

## 1. Overview

ECDAT is a cryptographic discovery and post-quantum migration decision-support system. It scans an organization's source code, binaries, containers, certificates, and infrastructure to build an evidence-backed inventory of every cryptographic asset in use, scores each asset's quantum-risk urgency, and produces purpose-aware recommendations for migrating to NIST-standardized post-quantum cryptography (PQC) — without ever making changes automatically.

ECDAT is **not** an auto-remediation tool. It is a read-only advisory and reporting system: it tells an organization what it has, how urgent the risk is, and what to do about it — the organization's own teams decide when and how to act.

---

## 2. Problem Statement

Organizations do not know where they use quantum-vulnerable cryptography. As a result, they cannot plan a realistic migration to post-quantum algorithms, even though:

- Cryptography is embedded across source code, compiled binaries, libraries, certificates, configuration files, and live infrastructure — most of it invisible to the people who own the system.
- Not all vulnerable cryptography carries equal urgency. Risk depends on how long protected data must remain secret versus how soon a cryptographically-relevant quantum computer might exist (Mosca's theorem), and whether an attacker could already be harvesting that data today for later decryption (Harvest-Now-Decrypt-Later, HNDL).
- Migrating an algorithm is not a single swap — it has downstream effects on protocols, hardware, vendors, storage, bandwidth, and compliance obligations.
- This is a standards-driven, government-aligned problem space. India's TEC 910018:2025 report and NIST's PQC migration project both frame this as an organizational/national readiness problem, not a narrow technical one.

**Reframing:** ECDAT is not "a crypto scanner." It is a decision-support system for quantum migration — the distinction that shapes every requirement below.

---

## 3. Who This Is For

ECDAT is built for organizations that must demonstrate cryptographic readiness against a regulatory or national-standards baseline, and for the technical teams inside them who are accountable for that readiness. Concretely:

- **Government IT security teams and CISOs** of critical infrastructure and citizen-facing systems, who must show compliance against frameworks like TEC 910018:2025.
- **Security/compliance auditors** who need an evidence-backed inventory rather than a self-reported checklist.
- **Engineering leads and platform teams** who own the applications where the actual migration work will happen, and need actionable, prioritized guidance rather than a raw list of findings.

ECDAT is explicitly **not** built as a consumer tool, a penetration-testing tool, or an auto-remediation platform.

---

## 4. Goals and Non-Goals

### Goals
- Discover cryptographic usage across five surfaces: source code, binaries/libraries, containers, certificates/keys, and infrastructure/cloud metadata.
- Produce an evidence-backed, deduplicated cryptographic asset inventory.
- Score each asset's quantum-risk urgency using an explainable model (Mosca's theorem + HNDL).
- Recommend NIST-standard PQC replacements that are purpose-aware (key establishment vs. digital signature) and standardization-status-aware (finalized vs. ongoing).
- Quantify the real-world impact of migrating each asset (bandwidth, storage, protocol, hardware, vendor, cost).
- Export a schema-valid CycloneDX CBOM and present findings through a dashboard.

### Non-Goals (explicitly out of scope for this system)
- Automatically patching code, rotating keys, or replacing certificates.
- Live HSM integration or full enterprise-wide network scanning.
- Acting as a general-purpose SAST/security scanner beyond cryptography.
- Continuous, always-on monitoring (the prototype performs point-in-time scans).

---

## 5. Functional Requirements

The system is a linear pipeline with two labeled branch/merge points. Each stage below is a functional requirement; the pipeline order is fixed.

| # | Stage | Requirement |
|---|---|---|
| 1 | **Inputs** | Ingest source repositories, binaries/libraries, container images, certificates/keys, and infrastructure/cloud metadata. |
| 2 | **Source & Binary Discovery** | Apply the detection mechanism appropriate to each input type: AST analysis (source), binary fingerprinting (compiled artefacts), layer inspection (containers), dedicated parsers (certificates), and a TLS/SSH probe (infrastructure). Output splits into deterministic findings and ambiguous findings. |
| 3a | **Deterministic Findings** | Clear, rule-based cryptographic matches pass through without further review. |
| 3b | **LLM Enrichment** | Ambiguous findings only. Must apply, in order: secret scrubbing, prompt-injection stripping, cache lookup by snippet hash, LLM call (temperature = 0, versioned prompt), and JSON-schema validation of the output before it is accepted. The LLM must never issue a final security verdict — only classification of ambiguous purpose/context. |
| 4 | **Evidence Engine** | Every finding (deterministic or LLM-assisted) must carry location, source, detection method, and a weighted composite confidence score. |
| 5 | **Crypto Asset Inventory** | Deduplicate and correlate findings into a single asset record per unique cryptographic asset, including algorithm, key metadata, purpose, owner, and classification fields. |
| 6 | **Classification & Business Context** | Tag each asset as application or infrastructure cryptography (TEC 910018:2025 taxonomy), with sensitivity, business criticality, and lifecycle stage. |
| 7 | **Reachability & Context** | Trace each asset through application → function → protocol → data → execution path to determine actual exposure rather than raw presence. |
| 8 | **Discovery Completeness** | Compute a coverage percentage: found asset categories vs. expected categories, across all source types. |
| 9 | **Mosca Risk Engine** | Compute quantum-risk urgency explicitly as X (data security shelf life) + Y (expected migration time) compared against Z (estimated threat timeline); flag urgency when X + Y > Z. Weight by classification, reachability, and an HNDL exposure flag. |
| 10 | **PQC Recommendation Engine** | Map algorithm + purpose to the correct NIST-standard replacement (ML-KEM for key establishment; ML-DSA or SLH-DSA for signatures). Keep standardized algorithms separate from those still under standardization (e.g. HQC, Falcon), and never recommend the latter as primary. Recommend hybrid (classical + PQC) by default during migration, pure-PQC only for greenfield systems. Output is strictly read-only/advisory. |
| 11 | **Migration Impact Analysis** | Score each recommendation against real migration factors (bandwidth, storage, latency, protocol, application software, hardware/HSM, vendor dependency, cost) and render the result as a roadmap-style sequence (current state → risk → recommendation → affected components → priority → validation steps), not a bare score. |
| 12 | **Outputs** | Produce three destinations: a schema-validated CycloneDX CBOM export (with quality score and version-diff support), consolidated migration & certificate reports, and a dashboard presenting findings, evidence, risk, reachability, completeness, ownership, HNDL flags, a dependency graph, and a crypto-agility score. |

---

## 6. Non-Functional Requirements

- **Confidentiality by design.** The prototype operates only on public, already-open-source data (public GitHub repositories, OpenSSL builds) to remove any confidentiality risk from LLM enrichment. In a real deployment, secrets/credentials must never leave the local environment (enforced by the secret scrubber stage).
- **LLM output must never bypass validation.** All LLM output is constrained to structured JSON and validated against a schema before being merged into the inventory; malformed or out-of-schema output is rejected, not coerced.
- **Determinism first.** The deterministic engine is always the primary source of truth; the LLM is secondary and advisory only, consistent with published research showing LLMs are unreliable as sole judges of security correctness.
- **Explainability.** Every finding must be traceable to its evidence (location, detection method, confidence) — the system must always be able to answer "how do you know?"
- **Data sensitivity of ECDAT's own outputs.** The inventory, CBOM, and reports themselves are sensitive artifacts (they describe an organization's weak points) and must be access-controlled, not distributed as freely as a generic report.
- **Reproducibility.** LLM prompt versions must be tied to cache keys, so a prompt update never silently mixes old and new cached results.
- **Read-only guarantee.** No stage of the pipeline may modify source systems, rotate keys, or apply patches under any configuration.

---

## 7. Architecture Summary

```
Inputs (5 surfaces)
   → Source & Binary Discovery (AST / fingerprint / layer / cert / infra probe)
        → Deterministic Findings ──────┐
        → LLM Enrichment (scrub → strip → cache → LLM → schema-validate) ──┐
                                                                             ↓
                                                                  Evidence Engine
                                                                             ↓
                                                                  Crypto Asset Inventory
                                                                             ↓
                                                                  Classification & Business Context
                                                                             ↓
                                                                  Reachability & Context
                                                                             ↓
                                                                  Discovery Completeness
                                                                             ↓
                                                                  Mosca Risk Engine (X+Y>Z, HNDL)
                                                                             ↓
                                                                  PQC Recommendation Engine
                                                                             ↓
                                                                  Migration Impact Analysis (roadmap)
                                                                             ↓
                                              ┌──────────────────────────────┼──────────────────────────────┐
                                       CBOM Export              Migration & Cert Reports              Dashboard GUI
```

This architecture is frozen for the prototype. Refinements identified through TEC/NIST/IEEE review (infrastructure scanner, migration roadmap framing, purpose-aware PQC mapping, crypto-agility, ownership fields) are folded into existing stages rather than added as new boxes.

---

## 8. Technology Stack

| Layer | Technology | Reason |
|---|---|---|
| Source parsing | Python + tree-sitter | Multi-language AST parsing avoids regex false positives (e.g. matching "RSA" in a comment). |
| Binary analysis | pyelftools / LIEF | Mature, tested parsers for ELF/PE symbol and import extraction. |
| Certificate parsing | cryptography (pyca) | Direct X.509 parsing (issuer, subject, key algorithm, size, expiry) in a few lines. |
| Infrastructure probe | Python `ssl`/`socket`, `paramiko` | Lightweight TLS/SSH handshake inspection without needing a full scanner framework. |
| Secret detection | `detect-secrets` / entropy checks | Established approach for catching key-like strings before they leave the local process. |
| Caching | Redis | Fast, hash-keyed lookup to avoid repeat LLM calls on identical snippets. |
| LLM enrichment | Claude/GPT API, temperature = 0, versioned prompts | Minimizes non-determinism; versioning avoids silent drift in interpretation. |
| Schema validation | `jsonschema` / `pydantic` | Hard enforcement that LLM output cannot introduce unvalidated fields into the inventory. |
| Data storage | PostgreSQL | Relational joins needed across evidence, inventory, classification, and risk tables. |
| Reachability graph | NetworkX | Lightweight call-graph construction and traversal, sufficient for prototype-scale reachability analysis. |
| Recommendation/lookup logic | JSON/YAML config + Python | Keeps algorithm-to-PQC mappings and ownership mappings as editable data, not hardcoded logic — important as NIST standards evolve. |
| Report rendering | Jinja2 + WeasyPrint/reportlab | Separates roadmap narrative (presentation) from impact scoring (data). |
| CBOM export | cyclonedx-python-lib | Guarantees schema-correct CycloneDX output rather than hand-built JSON. |
| Backend API | FastAPI | Fast to build, serves inventory/risk data to the dashboard. |
| Dashboard frontend | React + Recharts/D3 | Supports the dependency graph and risk visualizations required by the dashboard. |

---

## 9. Sample Output Artifact

A single crypto asset record, as it appears in the inventory and feeds the CBOM export:

```json
{
  "asset": "RSA-2048",
  "purpose": "key_establishment",
  "location": "auth_service.py:143",
  "library": "OpenSSL 1.1.1",
  "protocol": "TLS 1.2",
  "classification": "application",
  "sensitivity": "high",
  "business_criticality": "critical",
  "owner": "Citizen Services Team",
  "reachable": true,
  "evidence": {
    "detection_method": "AST rule R-014",
    "confidence": 0.98
  },
  "risk": {
    "mosca_x_years": 15,
    "mosca_y_years": 2,
    "mosca_z_years": 12,
    "urgency_flag": true,
    "hndl_flag": true,
    "priority": "P1"
  },
  "recommendation": {
    "standardized_replacement": "ML-KEM (FIPS 203)",
    "migration_path": "hybrid: X25519 + ML-KEM",
    "status": "standardized"
  }
}
```

---

## 10. Success Metrics

- **Detection quality:** precision, recall, F1, false-positive/false-negative rate against a controlled test set with known ground truth.
- **CBOM quality:** completeness, correctness, duplicate rate, evidence coverage of the exported inventory.
- **LLM contribution (measured, not assumed):** false-positive reduction, latency, cost, and consistency of deterministic+LLM vs. deterministic-only.
- **Risk engine behavior:** verified against synthetic low/medium/high-risk organizational profiles to confirm prioritization behaves as expected.
- **Migration recommendation accuracy:** checked against the ground-truth test set for correctness of purpose-aware mapping.

---

## 11. Known Limitations (Prototype Scope)

Stated proactively rather than left for review:

- Source-language coverage limited to Python, Java, C/C++, and JavaScript for the prototype.
- Reachability analysis is call-graph-based (via NetworkX), not full inter-procedural data-flow analysis.
- Infrastructure scanning is demonstrated against a defined set of endpoints, not a full enterprise network sweep.
- Container analysis covers layer/package inspection, not deep binary analysis of every packaged artifact.
- Evaluation datasets are synthetic or drawn from public repositories; results will not fully generalize to arbitrary production codebases without further validation.

---

## 12. Future Scope (Named, Not Built)

- **CBOM drift / continuous monitoring** — detecting newly introduced vulnerable crypto over time via scheduled re-scans against a persistent baseline.
- **Live HSM integration** — querying real hardware security modules directly rather than working from static vendor-spec data.
- **Full enterprise network scanning** — scaling the infrastructure probe from demonstrated endpoints to an entire live network.
- **Cloud-provider-wide discovery** — deep integration with AWS KMS/Azure Key Vault/GCP KMS for automatic managed-service discovery.
- **Automated production migration** — actually executing key rotation, certificate replacement, or code rewrites (deliberately excluded; ECDAT stays advisory-only).
- **Full interoperability/validation sandbox** — live handshake latency and compatibility testing of PQC swaps, beyond referencing published benchmark data.
- **Full SIEM/enterprise monitoring integration** — piping findings into existing security operations tooling.
- **What-if PQC migration simulator** — hypothetical "swap this algorithm and show the blast radius" simulation, requiring the full dependency graph plus a working impact-recalculation engine.

---

## 13. Positioning Statement

ECDAT's contribution is integration, not invention. Tools like CryptoPyt and Cryptolation already perform precise cryptographic API detection; CycloneDX and NIST NCCoE already define CBOM and migration frameworks. ECDAT connects discovery, evidence-backed inventory, reachability-aware and HNDL-adjusted quantum-risk scoring, and purpose-aware migration recommendation into one coherent workflow explicitly aligned to TEC 910018:2025 and current NIST PQC standards — where existing research and tooling each solve one piece of this problem in isolation.

> A cryptographic asset should not be represented merely as "RSA-2048 detected." ECDAT associates the cryptographic primitive with its purpose, code location, dependency, protocol, protected data, reachability, business criticality, lifetime, and migration constraints — producing an evidence-backed inventory and an actionable, purpose-aware PQC migration recommendation.
