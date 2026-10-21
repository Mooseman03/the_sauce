Write-Host "Starting data collection..."

New-Item -ItemType Directory -Force -Path collected_data

# Collect process data
Write-Host "Collecting process data..."

Get-CimInstance Win32_Process |
Select ProcessId,ParentProcessId,Name,ExecutablePath,CommandLine |
ConvertTo-Csv -NoTypeInformation |
Out-File collected_data/processes.txt -Encoding utf8


# Collect network connections
Write-Host "Collecting network data..."

Get-NetTCPConnection |
Select LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess |
ConvertTo-Csv -NoTypeInformation |
Out-File collected_data/network.txt -Encoding utf8

# Collect Application logs
Write-Host "Collecting Application logs..."

Get-EventLog -LogName Application -Newest 100 |
Select TimeGenerated,EntryType,Source,EventID,Message |
ConvertTo-Csv -NoTypeInformation |
Out-File collected_data/application_log.txt -Encoding utf8


# Collect Security logs
Write-Host "[*] Collecting Security logs..."

Get-EventLog -LogName Security -Newest 100 |
Select TimeGenerated,EntryType,Source,EventID,Message |
ConvertTo-Csv -NoTypeInformation |
Out-File collected_data/security_log.txt -Encoding utf8


# Collect System logs
Write-Host "[*] Collecting System logs..."

Get-EventLog -LogName System -Newest 100 |
Select TimeGenerated,EntryType,Source,EventID,Message |
ConvertTo-Csv -NoTypeInformation |
Out-File collected_data/system_log.txt -Encoding utf8


Write-Host "[+] Data collection complete."
