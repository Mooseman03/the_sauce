# Software Development Life Cycle — the_sauce

This public-facing SDLC summary is adapted from the original NET-351 Python final-project plan and aligned with the supplied Python and PowerShell source code. The original document included proposed features; this version separates delivered behavior from future work.

## 1. Planning

**Problem:** Security analysts may need to inspect running processes, network connections, and Windows event logs separately. The tool brings selected information into CSV reports to support initial review.

**Project:** `the_sauce` (`the_sauce.py` and `collect_data.ps1`).

**Scope:** Windows local-system data collection using PowerShell and Python-based parsing, hashing, correlation, and heuristic scoring.

**Security considerations:** Some collected data includes sensitive paths, command lines, addresses, and log messages. Elevated privileges may be necessary. Reports should be stored securely and excluded from public repositories.

## 2. Requirements analysis

**Inputs:** `Win32_Process`, TCP connection data, and the latest 100 Application, Security, and System event-log records from Windows PowerShell.

**Outputs:** A flat process-analysis CSV and three event-log CSVs, written to `Reports/`.

**Dependencies:** Windows PowerShell, Python, and pandas.

## 3. Design

**Collection layer:** `collect_data.ps1` writes five CSV-formatted `.txt` files into `collected_data/`.

**Analysis layer:** `the_sauce.py` loads those files with pandas, calculates executable SHA-256 hashes, applies scoring rules, maps TCP connections by owning PID, and searches event-message text for PID strings.

**Reporting layer:** Four CSV files are exported. The process report includes PID and PPID but does not build a graphical or nested process tree.

## 4. Implementation

Implemented: Windows process and TCP collection; three Windows event-log collections; executable hashing; rule-based risk scores; risk-level labels; basic PID-based mapping; CSV export; runtime measurement.

Not implemented in the supplied code: VirusTotal integration, Sysmon ingestion, JSON export, GUI, and MITRE ATT&CK mapping.

## 5. Testing and verification

The original SDLC described planned unit, integration, and performance testing. The supplied code alone does not establish which tests were completed. Recommended validation includes successful and failed PowerShell collection, missing data files, restricted executables, expected risk scores, and false-positive event matches.

## 6. Deployment

Keep `the_sauce.py` and `collect_data.ps1` together. Install `pandas` from `requirements.txt`, launch an elevated Windows PowerShell session where necessary, and run `python the_sauce.py`. Inspect the generated CSV files locally.

## 7. Maintenance and future work

Improve subprocess error checking, hash files in chunks, correlate event records more precisely, add tests, and consider optional threat-intelligence lookups and additional output formats. Review dependencies and protect generated reports.
