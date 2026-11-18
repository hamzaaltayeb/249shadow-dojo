# 249Shadow Cyber Lab — Web Security Module

Welcome to the **Web Security** track of the **249Shadow Cyber Lab**.

## Module Overview

Practical web application security challenges focused on broken object-level authorization (IDOR/BOLA), request inspection, session validation, and database query injection vulnerabilities.

Modern web architectures and enterprise microservices depend heavily on rigorous access-control verification and robust query boundary separation. When backend endpoints trust client-supplied object identifiers without validating caller authorization, or when user input is concatenated directly into structured database queries, critical administrative data and confidential records become vulnerable to unauthorized retrieval.

This module challenges participants to analyze, probe, and exploit fundamental web application flaws:

1. **Broken Object-Level Authorization (IDOR/BOLA):** Inspecting client-server HTTP communications, evaluating session token scope, identifying predictable object references, and retrieving restricted operational records across administrative boundaries.
2. **Structured Query Injection (SQLi):** Auditing unparameterized search endpoints, detecting SQL syntax termination points, enumerating database schema structures through controlled UNION queries, and extracting sensitive archival payloads.

## Official Challenge Lineup

- **Borrowed Identity (Easy — 50 Points):** Investigate an internal personnel records management portal, analyze object identifier parameters, and exploit broken authorization checks to access a classified investigation brief.
- **Query Under Pressure (Medium — 100 Points):** Audit an enterprise archival document search service, identify unparameterized SQL concatenation, discover hidden database tables, and extract confidential intelligence records via UNION-based injection.

## Submission Instructions

Each challenge initiates an isolated, local application service inside your workspace environment accessible at `http://127.0.0.1:5000` (or via the **Web** interface tab on port 5000). Accompanying case briefs and connection parameters are placed dynamically in `/challenge/` (and mirrored to `/home/hacker/`).

Submit recovered flags in the standard format:
`249shadow{...}`
