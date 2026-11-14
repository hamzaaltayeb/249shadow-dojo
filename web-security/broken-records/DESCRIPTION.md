# Broken Records

## Scenario

You have joined the 249shadow security team as a Junior Security Operations Center (SOC) analyst. As part of your onboarding, your team lead has provided you access to the internal **Department of Records & Archives** web portal.

The archive manages personnel profiles, department checklists, and operational shift logs. Rumors in the department suggest that sensitive administrative audit memorandums and cryptographic security keys are archived in the same system.

## Objective

Investigate the record management web application, understand how individual records are referenced and accessed, and retrieve the flag contained within the restricted Directorate audit record.

## Application Entry Point

The application runs inside your workspace environment:

- **Web Workspace Interface:** Switch to the **Web** tab in the workspace bar.
- **Direct Workspace URL:** `http://localhost:5000` (port 5000).

You can interact with the application directly using the built-in browser interface or through terminal tools (`curl`, `python`) from the workspace Terminal.

## Starting Information

Use your assigned staff credentials to log into the portal:

- **Username:** `hacker`
- **Password:** `password123`

## Flag Format

`249shadow{...}`

Submit the retrieved flag in the workspace action bar input field to verify your solution.
