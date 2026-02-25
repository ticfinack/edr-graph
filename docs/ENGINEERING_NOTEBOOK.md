# Engineering Notebook — edr-graph

This notebook serves as a reverse-chronological design ledger for the edr-graph project. Each entry documents a significant design decision, milestone, or architectural change.

Entries follow the format:

- **ID**: Sequential identifier (EN-NNN)
- **Date**: YYYY-MM-DD
- **Author**: Name of the contributor
- **Category**: One of `architecture`, `milestone`, `design`, `security`, `performance`, `filing`
- **Subject**: Brief title
- **Description**: What was decided, built, or changed and why
- **References**: Links to commits, PRs, documents, or external resources

---

## EN-001 — Provisional Patent Filing & Archival Preservation

| Field | Value |
|---|---|
| **Date** | 2026-02-24 (filing) / 2026-02-25 (archival) |
| **Author** | Thomas Scott Williams |
| **Category** | `filing` |
| **Subject** | USPTO Provisional Patent Application Filed |

### Description

A provisional patent application was filed with the United States Patent and Trademark Office on 2026-02-24 for:

> **"System and Method for Process Ancestry Chain-Scoped Endpoint Security Enforcement Utilizing a Two-Tier Evaluation Engine with In-Memory Ancestry Acceleration"**

The application covers the two-tier evaluation engine (fast-path in-memory ancestry lookup + full graph query fallback), the process ancestry chain scoping mechanism, and the in-memory PID index acceleration structure.

On 2026-02-25, a cryptographic archival preservation was performed:

1. Repository snapshot at commit `8fc0bbad` (125 commits, full `.git/` history) archived to ZIP
2. All 5 USPTO filing PDFs archived separately
3. SHA-256 checksums computed for all archived materials
4. GPG detached signatures (RSA-4096, key `77591B7E69D52CA3`) applied to archives and checksum file
5. Signed annotated git tag `patent/provisional-filing-2026-02-25` created and pushed
6. Archive manifest with verification instructions created

### References

- Git tag: `patent/provisional-filing-2026-02-25`
- Commit: `8fc0bbad`
- Archive: `~/Documents/Archives/edr-graph-patent/2026-02-25/`
- GPG Key Fingerprint: `FE28 A558 BA5B FBCA AC9C ECA5 7759 1B7E 69D5 2CA3`

---

## EN-000 — Project Inception (Retrospective)

| Field | Value |
|---|---|
| **Date** | *TBD — please fill in* |
| **Author** | Thomas Scott Williams |
| **Category** | `milestone` |
| **Subject** | edr-graph Project Inception |

### Description

*This is a placeholder entry for a retrospective record of the project's inception. Please fill in the date, initial motivation, early design decisions, and any relevant context about how and why the project was started.*

### References

*Add links to any early design documents, conversations, or inspirations.*
