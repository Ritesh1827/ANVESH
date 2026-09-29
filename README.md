# ANVESH
### Enterprise Cryptographic Discovery & Post-Quantum Readiness

ANVESH is an evidence-driven cryptographic discovery and post-quantum readiness platform designed to help organizations understand where cryptography is being used, assess the associated risk, and plan migration toward post-quantum cryptography.

Originally developed as **ECDAT (Enterprise Cryptographic Discovery & Analysis Tool)** for Smart India Hackathon 2026, ANVESH brings cryptographic discovery, evidence collection, asset inventory, reachability analysis, risk prioritization and PQC migration recommendations into a single workflow.

---

## Why ANVESH?

Modern organizations depend on cryptography across applications, certificates, libraries, binaries and infrastructure.

The problem is simple to describe:

> You cannot migrate cryptography you cannot find.

In large environments, cryptographic usage can be distributed across source code, third-party dependencies, compiled binaries, certificates, containers and network-facing infrastructure.

Traditional scanning approaches can produce large numbers of findings without enough context to determine:

- What cryptographic asset was actually detected?
- Where was it found?
- What evidence supports the finding?
- Is it actually reachable or used?
- What is the business or security impact?
- What should replace it?
- Which assets should be migrated first?

ANVESH is designed to connect these steps into one evidence-backed workflow.

---

# Core Workflow

```text
Input Surfaces
	│
	▼
┌──────────────────────┐
│ Cryptographic       │
│ Discovery            │
└──────────┬───────────┘
	     │
	     ▼
┌──────────────────────┐
│ Evidence &           │
│ Asset Inventory      │
└──────────┬───────────┘
	     │
	     ▼
┌──────────────────────┐
│ Classification &     │
│ Context              │
└──────────┬───────────┘
	     │
	     ▼
┌──────────────────────┐
│ Reachability &       │
│ Relationships        │
└──────────┬───────────┘
	     │
	     ▼
┌──────────────────────┐
│ Risk & HNDL          │
│ Prioritization       │
└──────────┬───────────┘
	     │
	     ▼
┌──────────────────────┐
│ PQC Recommendation   │
│ & Migration Roadmap  │
└──────────┬───────────┘
	     │
	     ▼
┌──────────────────────┐
│ CBOM • Reports •     │
│ Evidence Trail       │
└──────────────────────┘
```
