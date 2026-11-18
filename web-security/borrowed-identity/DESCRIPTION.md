# Borrowed Identity

<badge>Easy</badge> • 50 Points

## Scenario

An internal records management portal is deployed across the operations division to store security incident reports, workstation audits, and classified case briefs. Each authorized employee is issued individual credentials to review and manage their assigned investigation files.

During a routine security audit, telemetry records indicated that the web application uses direct object identifiers to retrieve records from the backend database. While the portal requires valid credentials to log in, an analyst suspects that the application fails to enforce record ownership boundaries between different users.

Your mission is to authenticate using the provided test analyst account, inspect how the application handles record access, identify the authorization vulnerability, and retrieve the classified operational brief belonging to the Chief Forensic Inspector.

## Challenge Artifacts

Your workspace contains the investigation case file and access parameters:
- `/challenge/case-file.txt` (also mirrored at `/home/hacker/case-file.txt`)
- `/challenge/portal-url.txt` (also mirrored at `/home/hacker/portal-url.txt`)

The local portal service is reachable at:
`http://127.0.0.1:5000` (or via the **Web** workspace interface tab on port 5000).

## Vulnerability & Access Control Rules

- **Authentication Boundary:** The application requires a valid session cookie to interact with the records dashboard. Unauthenticated requests are rejected.
- **Object-Level Authorization:** When viewing or requesting an individual record, does the server verify that the requested record belongs to the currently authenticated analyst?
- **Flag Storage:** The flag is contained strictly within the body of the restricted investigation report. No flag or sensitive data is accessible through direct filesystem access.

## Tooling & Verification

The challenge can be solved using either:
- The built-in workspace browser (**Web** tab) and developer tools / network tab.
- Standard terminal tools such as `curl` using cookie jars (`-c` and `-b`) or Python `urllib.request`.

## Progressive Hints

<details>
<summary>Hint 1: Authentication & Normal Operation</summary>
Log in with the credentials provided in <code>case-file.txt</code> (<code>j.morrison</code> / <code>Password2026!</code>). Observe the records assigned to this user on the dashboard and click to view their details.
</details>

<details>
<summary>Hint 2: Parameter Inspection</summary>
Examine the URL and request parameters when viewing a record (e.g., <code>/record?id=101</code>). Notice that records are referenced by sequential numerical identifiers.
</details>

<details>
<summary>Hint 3: Direct Object Reference Manipulation</summary>
The authenticated user has access to records 101 and 102. What happens if you request a different record identifier (such as 103, 104, or 105) while keeping your valid session active?
</details>
