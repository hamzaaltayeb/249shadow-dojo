# Dotfile Trail

**Difficulty:** Easy · **Points:** 50 · **Category:** Linux & General Skills

---

## Scenario

You have been onboarded as an operations engineer and assigned workstation `WS-OPS-44`.
The previous engineer, Tariq, recently transferred to another department and left behind
a handover note in your home directory along with a `workspace/` tree containing project files,
configuration templates, logs, and archives.

Per departmental handover procedure, Tariq recorded the decommissioning signoff verification
flag inside an uncommitted hidden configuration file in the project tree before archiving the logs.

Your task is to navigate the workstation filesystem, locate the hidden handover artifact,
and recover the flag.

---

## Objective

1. Review the handover note `workstation-handover.txt` in your home directory.
2. Investigate the `workspace/` directory structure.
3. Locate the intended hidden handover artifact containing the signoff verification flag.
4. Read the flag and submit it.

---

## Guidance & Useful Commands

Linux hides files whose names begin with a dot (`.`). Standard directory listings (such as `ls`)
do not display them by default.

### Listing files including hidden files

```bash
ls -la
ls -la workspace/
```

### Finding hidden files recursively

```bash
find workspace -name ".*"
```

### Searching for text inside files

```bash
grep -rn "249shadow" workspace/
```

### Viewing file contents

```bash
cat <filename>
head -n 20 <filename>
```

---

## Files in Your Home Directory

| File / Directory | Description |
|------------------|-------------|
| `workstation-handover.txt` | Handover record and investigation briefing |
| `workspace/` | Directory tree containing projects, config, logs, and archives |

---

> **Tip:** You do not need root access or special permissions. All required files are in your workspace.
