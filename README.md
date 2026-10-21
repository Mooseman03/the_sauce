the_sauce

the_sauce is a Python and Windows PowerShell tool for collecting Windows process, TCP connection, and event-log data, correlating selected indicators, and exporting CSV reports for security review. Originally developed as a Python cybersecurity project.
Scope: This is a rule-based triage aid, not a malware detector. Risk scores are heuristic and may flag legitimate activity. Review findings manually.

Features
- Collects running processes with PID, parent PID (PPID), name, executable path, and command line using Get-CimInstance Win32_Process.
- Collects TCP connection details with Get-NetTCPConnection, including owning process IDs.
- Collects the newest 100 entries per log from the Windows Application, Security, and System event logs.
- Calculates SHA-256 hashes of accessible executable files.
- Correlates TCP connections to processes by PID and searches event-log message text for PID strings.
- Assigns rule-based risk scores and classifies them as Low, Medium, or High.
- Exports process-analysis and event-log reports as CSV files; prints elapsed execution time.
Requirements
- Windows with Windows PowerShell 5.1 and the relevant Windows management cmdlets.
- Python 3 with pandas installed.
- Administrator privileges are recommended and may be needed to read Security event logs and certain process details.
Installation
1. Download or clone this repository, keeping the_sauce.py and collect_data.ps1 in the same folder.
2. Open Windows PowerShell as Administrator and navigate to that folder.
3. Install the dependency:
   python -m pip install -r requirements.txt
   If the python command is unavailable, try py -m pip install -r requirements.txt and use py to run the script.
Usage
From the repository folder in Windows PowerShell:
python the_sauce.py
The Python script invokes collect_data.ps1 using Windows PowerShell, creates collected_data/ and Reports/, and writes CSV reports. The collection script uses -ExecutionPolicy Bypass for its child PowerShell process; review the script before running it.
Data flow
1. PowerShell collection: Writes CSV-formatted text files to collected_data/: processes.txt, network.txt, application_log.txt, security_log.txt, and system_log.txt.
2. Python analysis: Reads these files with pandas, hashes accessible executables, scores processes, and maps TCP connections and event IDs.
3. Reporting: Writes four files to Reports/:
   - process_tree_report.csv — a flat process report containing PID and PPID fields, not a rendered hierarchical process tree.
   - application_log_report.csv
   - security_log_report.csv
   - system_log_report.csv
Risk scoring
Indicator	Points
Executable path contains temp or appdata	+25
Process name is powershell.exe, cmd.exe, or wscript.exe	+20
Command line contains -enc or encodedcommand	+30
At least one TCP connection has the same owning PID	+15


Low: 0–29 · Medium: 30–59 · High: 60 or more.

The network indicator adds 15 points once per process, regardless of the number of connections. These indicators are not evidence of maliciousness on their own.
Limitations and security notes
- Event correlation currently searches for a PID as text within an event message, so unrelated numbers may match. It does not parse structured event process IDs.
- Some executable paths or hashes may be unavailable because of access restrictions or missing files.
- The script currently reads entire executables into memory when hashing them; large files can increase memory usage.
- The Python launcher does not currently check the PowerShell script's exit status, so collection errors may lead to incomplete or stale analysis.
- The PowerShell script collects only TCP connections (not UDP) and only the latest 100 entries from each selected event log.
- collected_data/ and Reports/ may contain usernames, file paths, command lines, network addresses, and security events. Do not commit real machine data or credentials to GitHub.
- No VirusTotal lookup or other external threat-intelligence integration is implemented in this version.
Future improvements
- More reliable event-to-process correlation and collection error handling.
- Chunked file hashing and automated tests.
- Optional VirusTotal hash lookup, Sysmon support, JSON export, and MITRE ATT&CK mapping.
- Graphical interface and true hierarchical process-tree visualization.
Development documentation
See [Software Development Life Cycle](docs/SDLC.md) for the project design, implemented features, limitations, and planned improvements.
License
MIT — see LICENSE.
