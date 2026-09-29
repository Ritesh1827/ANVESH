# ECDAT Build Execution Plan — 8–10 Day Prototype (SIH Selection Round)

*Companion to ECDAT_PRD.md. This version replaces the original multi-week phasing with a compressed sequence scoped to a reviewer-facing prototype, plus an explicit section on what stays as named future work for the December main round.*

---

## Core principle (unchanged from the original plan)

The 12 pipeline stages are sequential dependencies, not independent modules. Build one thin, working, end-to-end slice first — prove the pipeline runs start to finish — then widen. Do **not** let Kiro scaffold all 12 stages as empty stubs up front; that produces code that looks complete in a demo but isn't wired together correctly, and it's harder to tell where the real gaps are once every stage already has a function signature.

## What's different in this version

The original phasing optimized for eventual production completeness (~4.5–5.5 weeks). This version optimizes for **what a reviewer will actually check against the PPT** in an 8–10 day window. Two consequences:

- **Reachability analysis and LLM enrichment move earlier.** They were last in the original plan because they're the highest-risk pieces technically — but they're also the deck's own stated differentiators (reachability is the Slide 2/3 justification for why ECDAT isn't "just a scanner"; the LLM-unreliability stats justify why it's secondary-only). A placeholder here is a credibility risk if a judge asks to see it work, not just a technical shortcut.
- **Input-surface breadth is deliberately narrowed, not the risk/recommendation logic.** Schema correctness, the Mosca engine, and the PQC recommendation engine stay full-depth throughout. Surface count (2–3 of 5 demoed) is the thing that flexes under time pressure.

---

## Day-by-day sequence

| Day | Focus | Notes |
|---|---|---|
| 1 | **Schemas** — Crypto Asset, Evidence, Risk, Recommendation, CBOM export shape (Pydantic models, matching PRD Section 9's sample JSON exactly) | Non-negotiable foundation; every later stage reads/writes these |
| 2–3 | **Source discovery → Evidence Engine → Crypto Asset Inventory**, wired end to end on one small, deliberately chosen test repo with known crypto calls (e.g. direct `RSA.generate()` / `hashlib.md5()` via PyCryptodome or OpenSSL bindings) | Deterministic rules only; skip LLM entirely here — hardcode a fallback for ambiguous findings |
| 4 | **Mosca Risk Engine + PQC Recommendation Engine**, built for real, not stubbed | Get purpose-aware branching correct now (RSA for key-exchange vs. signing must map differently) — this is the piece most likely to have a wrong-replacement bug if rushed |
| 5 | **Reachability & Context**, real but basic — call-graph on the same test repo via NetworkX | Moved up from "last" in the original plan; doesn't need full app→function→protocol→data tracing, just a working call-graph exposure check |
| 6 | **Widen input coverage** — add certificates (`cryptography`/pyca X.509 parsing, self-contained, quick win); add binaries/libraries only if ahead of schedule | Containers and infra probe become named next-steps, not demo requirements |
| 7 | **Minimal LLM enrichment** — secret scrubber → prompt-injection stripper → Redis cache (snippet hash) → LLM call (temp=0, versioned prompt) → JSON-schema validation gate | Test against one deliberately ambiguous snippet; confirm a repeat call hits cache instead of calling the LLM again |
| 8 | **CBOM export** (schema-valid via `cyclonedx-python-lib`) + **Migration Impact Analysis** roadmap-style text output | Scoring weights can stay fixed/simple; the roadmap narrative should be real since it's cheap and a differentiator |
| 9 | **Dashboard** — FastAPI endpoint serving inventory JSON, React table view, risk/priority color-coding, HNDL flags | Dependency-graph visualization and crypto-agility score are stretch additions, not required |
| 10 | **Integration + rehearsal** — run the real demo repo(s) end to end; verify every number the tool outputs matches what the PPT claims (Mosca inputs, HNDL example, purpose-aware mapping example) | Buffer day; this is also when scope cuts get finalized if behind schedule |

**If time runs out, cut in this order:** additional input surfaces → dashboard polish (dependency graph, agility score) → migration-impact scoring sophistication. **Never cut:** schema correctness, the Mosca engine, or the PQC recommendation logic — these are the specific claims the deck makes.

---

## Note on giving this to Kiro

- Paste this file and `ECDAT_PRD.md` into the same session/spec.
- Instruct it to complete Day 1 (schemas) and Days 2–4 (thin slice + real risk/recommendation engines) fully — including a working end-to-end run — before generating code for anything later.
- Ask it to flag anywhere implementation required deviating from the PRD's schema, rather than silently adjusting the schema on its own.
- Do not ask it to scaffold all 12 stages as stub functions up front "to see the shape of the system."

---

## What's real now vs. the December roadmap

This section exists so the PPT and the actual prototype never say different things — and so the December main round has a clear, honest starting point instead of a scramble.

**What the 8–10 day prototype will genuinely have working:**
- Full schema-correct pipeline, end to end, on 2–3 input surfaces (source code + certificates, binaries if time allows)
- A real Mosca Risk Engine (X + Y > Z, HNDL flag) — not hardcoded
- A real, purpose-aware PQC Recommendation Engine (ML-KEM vs. ML-DSA/SLH-DSA mapping)
- Basic but real reachability analysis (call-graph based, via NetworkX)
- A minimal but functioning LLM enrichment path (scrub → cache → call → validate)
- A schema-valid CycloneDX CBOM export
- A dashboard showing findings, risk/priority, and HNDL flags

**What stays as named future work — legitimate scope for December, not gaps to hide:**
- **Remaining input surfaces** — containers (layer inspection) and infrastructure/cloud metadata (TLS/SSH probe) (PRD Section 5, stage 1)
- **Full reachability depth** — the prototype uses call-graph analysis; true inter-procedural data-flow tracing (app → function → protocol → data → execution path) is explicitly named as a prototype limitation (PRD Section 11)
- **Broader language coverage** — prototype is limited to Python, Java, C/C++, JavaScript (PRD Section 11)
- **Formal evaluation** — precision/recall/F1 against a ground-truth test set, measured (not assumed) LLM contribution, and synthetic risk-profile validation (PRD Section 10, Success Metrics) — realistically not rigorously run in 8–10 days
- **Dashboard depth** — dependency graph visualization and crypto-agility score display, named as "last, once all underlying data is real" (original build plan, Phase 5)
- **Everything in PRD Section 12, Future Scope** — CBOM drift/continuous monitoring, live HSM integration, full enterprise network scanning, cloud-provider-wide discovery (AWS KMS/Azure Key Vault/GCP KMS), full interoperability/validation sandbox for real PQC handshake testing, SIEM integration, and the "what-if migration simulator"

**Positioning for the pitch:** a working end-to-end prototype demonstrating the full pipeline logic on a defined subset of surfaces, with a clearly scoped, already-planned roadmap to full surface coverage and formal evaluation — not a finished product presented as more complete than it is, and not a demo with hidden gaps a judge could catch.
