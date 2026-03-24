# Analyze-BHECompStatus.ps1

**BloodHound Enterprise — SharpHound Collection Status Analyser**  
PowerShell 5.1+

---

## What it does

SharpHound Enterprise writes a `*_compstatus.csv` file after each collection job. This script parses that file (or multiple files from several runs), categorises every result, and produces a self-contained interactive HTML report so you can quickly identify which computers failed, why, and what to fix.

---

## Quick start

Drop the script into the same folder as your compstatus CSV files and run it:

```powershell
.\Analyze-BHECompStatus.ps1
```

The script auto-discovers all `*compstatus*.csv` files in its directory. If it finds more than one, it shows a menu. The HTML report is written to a `Reports\` subfolder.

---

## Parameters

| Parameter | Default | Description |
|---|---|---|
| `-SearchFolder` | Script directory | Where to look for `*compstatus*.csv` files |
| `-OutputFolder` | `.\Reports\` | Where to write the HTML report |
| `-ReportTitle` | `BHE Collection Status Report` | Title prefix shown in the report header |
| `-NoMenu` | — | Skip the menu and analyse all discovered files immediately |

---

## Usage examples

```powershell
# Run interactively — auto-discovers CSVs, shows menu if multiple found
.\Analyze-BHECompStatus.ps1

# Point at a specific log folder, write reports elsewhere
.\Analyze-BHECompStatus.ps1 -SearchFolder "C:\BHELogs" -OutputFolder "C:\Reports"

# Custom title
.\Analyze-BHECompStatus.ps1 -ReportTitle "states.local — Weekly BHE Run"

# Non-interactive pipeline use — analyse all files, no prompts
.\Analyze-BHECompStatus.ps1 -NoMenu

# Run from a different working directory
.\Analyze-BHECompStatus.ps1 -SearchFolder "\\fileserver\bhelogs\2026-03" -OutputFolder "D:\Reports"
```

---

## Interactive menu (multiple files)

When more than one compstatus CSV is found, the script presents a numbered menu:

```
  +------------------------------------------------------+
  |  BloodHound Enterprise - CompStatus Analyser  v2.1  |
  |  SpecterOps TAM Toolkit                             |
  +------------------------------------------------------+

  [*] Found 3 compstatus file(s) in: C:\BHELogs

  Select an option:

    [1]  2026-03-22-09-00-01_1413_compstatus.csv   (18 KB)
    [2]  2026-03-23-09-00-02_1413_compstatus.csv   (19 KB)
    [3]  2026-03-24-10-38-02_1413_compstatus.csv   (21 KB)

    [4]  Compare ALL 3 files - cross-run report

  Enter choice: _
```

Choosing a single number produces a **Single Run** report for that file.  
Choosing the last option produces a **Multi-Run Comparison** report across all files.

---

## Report sections

The HTML report opens in any browser with no dependencies (Chart.js loads from CDN). All sections are collapsible. Clicking a summary card jumps directly to the relevant section and clears any active filters.

### Summary cards

![Summary cards showing 649 total results, 100 unique computers, 549 successful, 100 failed, 61 not active, 12 fully successful, 21 task-level errors](screenshots/01_summary_cards.png)

Seven clickable stat cards at the top of every report:

| Card | Jumps to |
|---|---|
| Total task results | Full Audit Log |
| Unique computers | Computers with Issues |
| Successful (84.6%) | Full Audit Log |
| Failed (15.4%) | All Failures |
| Not Active | Not Active list |
| Fully successful | Computers with Issues |
| Task-level errors | Computers with Issues |

### Failure distribution chart

![Donut chart showing failure breakdown by category](screenshots/02_chart.png)

Interactive donut chart with hover tooltips showing count and percentage per error category.

### Computer search (spotlight)

![Spotlight search bar showing results for WASHINGTON-DC01](screenshots/03_spotlight.png)

A sticky search bar pinned below the page header. Type any computer name — partial matches are supported. Separate multiple names with commas.

Each result card shows:
- Traffic-light status badge
- IP address · success count · failure count
- CSV line number(s) where the computer appears
- Error category badges
- Action links: **Issues Table** · **Audit Log** · **Failures Only**

Pressing **✕** or `Escape` clears the search and resets all table filters.

### Computers with Issues — Task Detail

![Computers with issues table](screenshots/04_issues_table.png)

One row per computer that has at least one failure. Columns:

| Column | Description |
|---|---|
| Computer | Canonical name (strips `host/` and `cifs/` prefixes) |
| IP Address | From the CSV, or Unknown |
| Tasks OK | Count of successful task results |
| Tasks Failed | Count of failed task results |
| Error Categories | Colour-coded badge(s) for each failure type |
| Status | Traffic-light badge (single file: red/orange/green; multi-file: cross-run) |
| File / Line(s) | CSV filename and line number(s) |

In multi-file mode a **Source File(s)** column is also added.

### All Failed Results

![All failures table filtered to show a specific computer](screenshots/05_failures_table.png)

Every failure row from the CSV. Filterable via the search box above the table.  
The **File / Line** column shows the exact filename and line number — e.g.:

```
2026-03-24-10-38-02_1413_compstatus.csv
L136
```

In multi-file mode each file contributing failures for the same computer appears as a separate row here.

### Remediation Guidance

![Remediation cards for AccessDenied and RPCError](screenshots/06_remediation.png)

A collapsible card for each error category found in the data, covering:

| Category | Typical cause |
|---|---|
| **NotActive** | Computer offline, VM powered down, stale AD object |
| **PortNotOpen** | TCP 445 or TCP 135 blocked by firewall or host policy |
| **AccessDenied** | SharpHound service account lacks NetWkstaUserEnum or LSA rights |
| **StatusAccessDenied** | LSAEnumerateAccountsWithUserRight — `SeSecurityPrivilege` needed |
| **RPCError** | RPC Endpoint Mapper (TCP 135) unreachable or Remote Registry not running |
| **RegistryError** | Remote Registry service running but ACL denies access to LSA key |
| **CollectorError** | Unhandled SharpHound exception — review full error in audit log |

Each card lists the affected computers by name.

### Not Active Computers

Collapsible list of all computers that failed the availability check and never had any further tasks attempted. In the sample CSV this is 61 of the 100 computers — typical for an environment with many stale AD objects or powered-down VMs.

### Full Audit Log

Every row from the source CSV with filename, line number, and full status detail. Fully filterable. Useful for copying specific error messages to share with the customer.

---

## Multi-file comparison mode

When comparing multiple runs, the report gains two additional sections:

### Files Analysed table

| File | Total Rows | Success | Failed | Success % | Status |
|---|---|---|---|---|---|
| 2026-03-22_compstatus.csv | 612 | 520 | 92 | 85.0% | 🟠 Mixed |
| 2026-03-23_compstatus.csv | 631 | 538 | 93 | 85.3% | 🟠 Mixed |
| 2026-03-24_compstatus.csv | 649 | 549 | 100 | 84.6% | 🟠 Mixed |

### All Computers — Cross-Run Status

Every unique computer listed once (no duplicates). Traffic-light reflects results *across all files*:

| Status | Meaning |
|---|---|
| 🟢 OK — All Files | Successful in every run it appeared in |
| 🟠 Mixed | Succeeded in some runs, failed in others |
| 🔴 Failed — All Files | Never succeeded across any run |

The **Files Containing Errors** column tags exactly which files recorded failures for that computer — useful for spotting intermittent issues vs persistent ones.

The **File / Line(s)** column in the Issues table groups by file:

```
2026-03-23_compstatus.csv: 141, 142, 165
2026-03-24_compstatus.csv: 136, 165, 166
```

---

## Error categories reference

| Category | Badge colour | Status value(s) in CSV |
|---|---|---|
| Success | Green | `Success` |
| NotActive | Grey | `NotActive` |
| PortNotOpen | Orange | `PortNotOpen` |
| AccessDenied | Red | `ErrorAccessDenied`, `AccessDenied` |
| StatusAccessDenied | Red | `StatusAccessDenied` |
| RPCError | Purple | `Collector failed: The RPC server is unavailable..` |
| RegistryError | Pink | `Collector failed: Failed to enumerate registry...` |
| CollectorError | Amber | Any other `Collector failed:` message |

---

## Sample CSV

A test file `sample_compstatus_100.csv` is provided covering all error categories using Solo Leveling character names on the `SOLO-LEVELING.COM` domain:

- **100 unique computers**, 649 total task rows
- **12 fully successful** (DCs and servers — Jinwoo, Ashborn, Antares, Baran, Bellion + servers)
- **61 NotActive** (offline workstations, laptops, VMs)
- **6 PortNotOpen** (Haein, Gunhee, Jinho, Joohee, Woonjinchul, ShadowExchange)
- **5 ErrorAccessDenied** (NetWkstaUserEnum denied — session data blocked)
- **5 StatusAccessDenied** (LSAEnumerateAccountsWithUserRight denied)
- **7 dual denied** (both NetWksta and LSA fail on same computer)
- **4 RPCError** (Remote Registry unreachable)
- **2 RegistryError** (long embedded-comma exception — tests parser robustness)
- **3 triple failure** (AccessDenied + StatusAccessDenied + RPC on same box)

The file matches the exact format SharpHound produces: UTF-8 BOM, CRLF line endings, space after each delimiter comma, 5-column header.

---

## Output file naming

Reports are written to the output folder with a timestamped name:

```
BHE-CompStatus-SingleRun_2026-03-24_11-05-32.html
BHE-CompStatus-MultiRun_2026-03-24_11-12-45.html
```

---

## Requirements

- PowerShell 5.1 or later (Windows)
- `Microsoft.VisualBasic` assembly (included in .NET Framework — standard on all Windows installs)
- Internet access from the browser to load Chart.js from CDN (`cdn.jsdelivr.net`). The report is otherwise fully self-contained.

---

## Notes

- The parser handles malformed CSV rows where SharpHound writes a long exception message containing embedded commas and quote characters (common for `RemoteRegistryStrategy` failures). These rows parse correctly — no data is lost.
- Computer names are canonicalised: `host/SERVERNAME.domain` and `cifs/SERVERNAME.domain` are de-prefixed and treated as the same computer as `SERVERNAME.domain`.
- `Set-StrictMode -Version Latest` is active throughout — if you extend the script, wrap any pipeline `.Count` calls in `@()`.

---

*SpecterOps TAM Toolkit — internal use*
