# the_sauce

**the_sauce** is a Python and Windows PowerShell cybersecurity tool that collects, correlates, and analyzes Windows process, Network connection, and event-log information. It generates CSV reports to support initial system security assessments and identify potentially suspicious activity.

The project was originally developed during the Spring 2026 semester as a final project for **NET-351 (Python) at Western Iowa Tech Community College (WITCC)** in Sioux City, Iowa.

**Project status:** Version 0.1.0 — Early development release.

**Scope:** This software is a rule-based security triage aid, not a malware detector. Risk scores are heuristic indicators and may flag legitimate system activity. Findings should always be reviewed manually.

## Features

- Collects running Windows processes, including process ID (PID), parent process ID (PPID), executable name, executable path, and command line using `Get-CimInstance Win32_Process`.
- Collects Network connection information using `Get-NetTCPConnection`, including owning process IDs.
- Retrieves the latest 100 entries from each of the Windows Application, Security, and System event logs.
- Calculates SHA-256 hashes of accessible executable files.
- Correlates Network connections with running processes using their PIDs.
- Searches Windows event-log messages for matching PID strings.
- Assigns heuristic risk scores and classifies processes as Low, Medium, or High risk.
- Exports process-analysis and event-log information to CSV reports.
- Measures and displays total execution time.

## Requirements

- Windows with Windows PowerShell 5.1 and the necessary Windows management cmdlets.
- Python 3.
- pandas Python library.
- Administrator privileges are recommended and may be required to access protected Windows event logs and certain process information.

## Installation

1. Download or clone this repository.
2. Keep `the_sauce.py` and `collect_data.ps1` in the same directory.
3. Open Windows PowerShell and navigate to the repository directory.
4. Install the required Python dependency:

```powershell
python -m pip install -r requirements.txt
```

If the `python` command is unavailable, try:

```powershell
py -m pip install -r requirements.txt
```

## Usage

Run the program from the repository directory:

```powershell
python the_sauce.py
```

The Python program launches `collect_data.ps1`, creates the required directories, processes the collected system information, and exports CSV reports.

The collection script is launched with PowerShell's `-ExecutionPolicy Bypass` option for its child process. Users should review the source code before execution.

Administrator privileges may be necessary for complete data collection.

## Data Flow

The program operates in three primary stages.

### 1. PowerShell Data Collection

The PowerShell script collects Windows system information and writes five CSV-formatted text files to the `collected_data/` directory:

- `processes.txt`
- `network.txt`
- `application_log.txt`
- `security_log.txt`
- `system_log.txt`

### 2. Python Analysis

The Python script reads the collected files using pandas and performs:

- Process identification using PID and PPID.
- SHA-256 executable hashing.
- Heuristic risk scoring.
- TCP connection mapping by owning PID.
- Basic Windows event-log correlation.

### 3. Report Generation

Four CSV reports are generated in the `Reports/` directory:

| Report | Description |
|---|---|
| `process_tree_report.csv` | Process information, executable hashes, risk scores, network connections, and mapped event IDs |
| `application_log_report.csv` | Collected Windows Application event-log records |
| `security_log_report.csv` | Collected Windows Security event-log records |
| `system_log_report.csv` | Collected Windows System event-log records |

Despite its filename, `process_tree_report.csv` currently provides a flat process listing containing PID and PPID information rather than a hierarchical process-tree visualization.

## Risk Scoring

The program assigns points to processes based on selected indicators.

| Indicator | Points |
|---|---:|
| Executable path contains `temp` or `appdata` | +25 |
| Process name is `powershell.exe`, `cmd.exe`, or `wscript.exe` | +20 |
| Command line contains `-enc` or `encodedcommand` | +30 |
| At least one TCP connection matches the process PID | +15 |

### Risk Classifications

| Risk Level | Score |
|---|---|
| Low | 0–29 |
| Medium | 30–59 |
| High | 60 or higher |

The network indicator contributes 15 points per process, regardless of the number of matching TCP connections.

**Important:** These indicators are not definitive evidence of malicious activity. Legitimate administrative tools and applications may receive elevated scores.

## Limitations and Security Notes

The current implementation has several known limitations:

- **Event correlation:** PID values are searched as text within event-log messages. Unrelated numbers may produce false matches.
- **Executable access:** Some executable paths and hashes may be unavailable because of access restrictions or missing files.
- **Memory usage:** Executable files are currently loaded entirely into memory before hashing, potentially increasing memory consumption for large files.
- **Collection error handling:** The Python script does not currently verify the PowerShell collection script's exit status. Collection failures may result in incomplete or outdated analysis.
- **Network collection:** Only TCP connections are collected; UDP activity is not included.
- **Event-log collection:** Only the newest 100 records from each selected Windows event log are collected.
- **Sensitive information:** Generated data may contain usernames, executable paths, command lines, network addresses, and security events.
- **Threat intelligence:** VirusTotal integration and other external threat-intelligence lookups are not implemented in version 0.1.0.

The `collected_data/` and `Reports/` directories should remain excluded from Git version control. Do not upload real system data, credentials, or sensitive reports to public repositories.

## Future Improvements

Planned or proposed enhancements include:

- Improved PowerShell collection error handling.
- More reliable event-to-process correlation.
- Chunked SHA-256 hashing for improved memory efficiency.
- Automated unit and integration testing.
- Optional VirusTotal hash lookups.
- Sysmon event-log integration.
- JSON report export.
- MITRE ATT&CK mapping.
- Hierarchical process-tree visualization.
- Graphical user interface.

These features are development goals and are not guaranteed to be implemented.

## Development Documentation

For a detailed explanation of the project's academic origins, requirements, architecture, implementation, testing considerations, and future development plans, see the [Software Development Life Cycle (SDLC)](docs/SDLC.md).

The SDLC documentation also includes the original project flowchart and an updated diagram representing the current implementation.

## Security and Liability Notice

`the_sauce` is an open-source Windows system security analysis tool intended for educational, research, and authorized defensive security purposes.

The software is provided **"AS IS"**, without warranties of any kind, as described in the MIT License.

**Important considerations:**

- Users are responsible for ensuring they have authorization to collect and analyze system information.
- The tool may require administrator privileges to access protected Windows event logs.
- Generated reports may contain sensitive information, including usernames, executable paths, command lines, and network addresses.
- Risk scores are heuristic indicators and should not be interpreted as definitive evidence of malicious activity.
- Users should independently verify findings before taking corrective actions.
- Users are responsible for protecting collected information and complying with applicable laws and organizational security policies.

The software is not intended to replace professional security assessment tools or independent security analysis.

See the [MIT License](LICENSE) for the full warranty disclaimer and limitation of liability.

## License

This project is licensed under the MIT License.

See the [LICENSE](LICENSE) file for details.
