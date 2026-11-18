# Midnight Maintenance

**Difficulty:** Medium · **Points:** 100 · **Category:** Linux & General Skills

---

## Scenario

During the early morning hours of November 15, operations alerts fired on production
server `srv-core-02`. Monitoring recorded an unapproved system maintenance task executing
between 03:00 and 04:00 UTC on a weekday, when maintenance windows are strictly restricted
to weekend change slots.

Before retiring and rebuilding the affected server, an incident responder collected a forensic
system snapshot under `server-snapshot/` along with an initial incident report.

Your objective as an investigator is to reconstruct the execution trail:
1. Identify the misconfigured scheduled cron job responsible for the unexpected run.
2. Correlate cron and service logs to identify the exact execution ID and timestamp.
3. Trace the maintenance script invoked by cron to determine its output location.
4. Locate and inspect the resulting maintenance audit report to recover the diagnostic validation token (flag).

---

## Structure of the System Snapshot

```text
server-snapshot/
├── etc/
│   ├── crontab
│   ├── cron.d/               # Scheduled task definitions
│   └── environment
├── usr/
│   └── local/
│       └── sbin/             # Administrative shell scripts
├── var/
│   └── log/                  # System & service logs
│       ├── cron.log
│       └── maintenance/      # Maintenance execution logs and reports
└── home/
    └── operator/             # Operator scratch notes
```

---

## Investigation Clues & Linux Commands

- **Cron configurations:** Inspect `/etc/cron*` files. Look closely at the minute, hour, day-of-month, month, and day-of-week fields (`m h dom mon dow`).
- **Log correlation:** Use `grep`, `awk`, or `cut` on `var/log/cron.log` and `var/log/maintenance/maintenance.log` to match the 03:00–04:00 UTC incident window.
- **Script tracing:** View scripts under `usr/local/sbin/` to see where logs and reports are routed.
- **Compressed logs:** Log rotation and maintenance routines frequently compress reports using `gzip`. Tools like `zcat`, `gunzip -c`, or `zgrep` allow inspecting compressed `.gz` files directly without permanent extraction.

### Useful Command Examples

```bash
# Search cron logs for events around 03:00
grep "03:" server-snapshot/var/log/cron.log

# Search maintenance logs for run IDs
grep "2024-11-15" server-snapshot/var/log/maintenance/maintenance.log

# Inspect a compressed report file
zcat server-snapshot/var/log/maintenance/reports/<report-name>.log.gz
# or
zgrep "Token" server-snapshot/var/log/maintenance/reports/<report-name>.log.gz
```

---

## Files in Your Home Directory

| File / Directory | Description |
|------------------|-------------|
| `incident-report.txt` | Initial SOC incident report with timeline and scope |
| `server-snapshot/` | Preserved forensic filesystem snapshot |

---

> **Tip:** This challenge tests systematic Linux log analysis and script tracing.
> No actual cron daemons or services need to be started. All files are static forensic artifacts.
