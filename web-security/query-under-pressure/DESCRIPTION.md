# Query Under Pressure

<badge>Medium</badge> • 100 Points

## Scenario

An internal document-search portal was recovered from a decommissioned application server during an infrastructure assessment. The portal allows employees across departments to search the organization's archival records library, including network defense plans, incident response protocols, and security guidelines.

Preliminary code review indicates that the legacy search handler directly interpolates user-provided search terms into backend SQL query strings rather than utilizing parameterized queries or prepared statements. Intelligence reports suggest that the database also maintains a restricted classification archive containing sensitive operational records.

Your objective is to assess the search endpoint, identify the SQL injection point, determine the underlying database structure through controlled UNION-based queries, enumerate the database schema, and extract the classified intelligence payload containing the competition flag.

## Challenge Artifacts

Your workspace contains the incident briefing and connection details:
- `/challenge/incident-brief.txt` (also mirrored at `/home/hacker/incident-brief.txt`)
- `/challenge/search-portal.txt` (also mirrored at `/home/hacker/search-portal.txt`)

The local search portal is reachable at:
`http://127.0.0.1:5000` (or via the **Web** workspace interface tab on port 5000).

## Vulnerability & Database Architecture

- **Search Query Construction:** The backend search routine executes a single SQL query matching search terms against document titles and summaries.
- **Engine Security Policy:** The database operates in strict query-only mode (`PRAGMA query_only = ON`). Multi-statement stacked queries, table alteration, and write operations are strictly disallowed.
- **Exploitation Path:** Successful recovery requires discovering the exact number and layout of projected columns, inspecting SQLite's internal metadata catalog (`sqlite_master`), locating the restricted archive table, and projecting its confidential payload into the result set.
- **Flag Storage:** The flag is contained strictly within a restricted archival record in the database. No flag or sensitive data is accessible through direct filesystem access.

## Tooling & Verification

The challenge can be solved using either:
- The built-in workspace browser (**Web** tab) and developer tools.
- Terminal utilities such as `curl` using URL-encoded query parameters or Python `urllib.request`.

## Progressive Hints

<details>
<summary>Hint 1: Query Syntax & Error Analysis</summary>
Perform legitimate searches using terms like <code>perimeter</code>, <code>telemetry</code>, or <code>incident</code> to observe standard output. What happens when you supply a single quote character (<code>'</code>)? Review the resulting database error message carefully.
</details>

<details>
<summary>Hint 2: Column Count &amp; UNION Projection</summary>
Use a controlled <code>UNION SELECT</code> statement to determine the exact number of columns returned by the original query (e.g., <code>' UNION SELECT 1, 2, 3, 4 --</code>). Adjust the number of constants until the query executes cleanly without column-count mismatch errors.
</details>

<details>
<summary>Hint 3: Schema Enumeration in SQLite</summary>
Once you have matched the column count, query SQLite's internal schema catalog (<code>sqlite_master</code> or <code>sqlite_schema</code>) to discover what tables and columns exist in the database. Look for tables containing classified or restricted project data.
</details>
