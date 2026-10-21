import os
import subprocess
import hashlib
import pandas as pd
import time

REPORTS_FOLDER = "Reports"
DATA_FOLDER = "collected_data"


# CREATE FOLDERS
def make_folders():
    os.makedirs(REPORTS_FOLDER, exist_ok=True)
    os.makedirs(DATA_FOLDER, exist_ok=True)


# RUN PS1 FILE (Windows was having trouble finding the bash script during testing and switching to PS1 was the easiest solution)
def run_collection_script():

    print("Running collection script...")

    subprocess.run(
    [
        "powershell",
         "-ExecutionPolicy",
         "Bypass",
         "-File",
         "collect_data.ps1"
    ]
    )



# HASH FILE
def hash_file(path):

    if not isinstance(path, str):
        return "N/A"

    if not os.path.exists(path):
        return "N/A"

    try:
        with open(path, "rb") as file:
            data = file.read()
            return hashlib.sha256(data).hexdigest()

    except FileNotFoundError:
        return "Error: File not found."
    except PermissionError:
        return "Error: Permission Denied"
    except OSError:
        return "Error: Hash Error"



# RISK SCORING CALCULATING
def calculate_risk(name, path, command_line, pid, network_df):

    score = 0
    reasons = []
    mapped_network = []

    name = str(name).lower()
    path = str(path).lower()
    command_line = str(command_line).lower()

    if "temp" in path or "appdata" in path:
        score += 25
        reasons.append("Temp/AppData")

    if name in ["powershell.exe", "cmd.exe", "wscript.exe"]:
        score += 20
        reasons.append("Suspicious Process")

    if "-enc" in command_line or "encodedcommand" in command_line:
        score += 30
        reasons.append("Encoded Command")

    if (
        not network_df.empty and
        "OwningProcess" in network_df.columns
    ):
        matching_connections = network_df[network_df["OwningProcess"] == pid]

        if not matching_connections.empty:
            score += 15
            reasons.append("Network Activity")

            for _, net_row in matching_connections.iterrows():
                mapped_network.append(
                    f"{net_row['LocalAddress']}:{net_row['LocalPort']} -> "
                    f"{net_row['RemoteAddress']}:{net_row['RemotePort']} "
                    f"({net_row['State']})"
                )
    return score, ", ".join(reasons), " | ".join(mapped_network)
# MAPPED EVENT LOGS TO PID
def map_event_ids_to_process(pid, application_df, security_df, system_df):

    mapped_events = []

    all_logs = [
        application_df,
        security_df,
        system_df
    ]

    for log_df in all_logs:
        if not log_df.empty and "Message" in log_df.columns and "EventID" in log_df.columns:
            matches = log_df[log_df["Message"].astype(str).str.contains(str(pid), na=False)]

            for _, log_row in matches.iterrows():
                mapped_events.append(str(log_row["EventID"]))

    return ", ".join(sorted(set(mapped_events)))

# RISK LEVEL
def risk_level(score):

    if score >= 60:
        return "High"

    elif score >= 30:
        return "Medium"

    else:
        return "Low"

def read_data_file(file_name):
    file_path = os.path.join(DATA_FOLDER, file_name)

    if not os.path.exists(file_path):
        print(f"[!] File not found:{file_path}")
        return pd.DataFrame()

    return pd.read_csv(
        filepath_or_buffer=file_path,
        encoding="utf-8",
        sep=",",
        engine="python"
    )

# ANALYZE DATA
def analyze():
    process_df = read_data_file("processes.txt")
    network_df = read_data_file("network.txt")
    application_df = read_data_file("application_log.txt")
    security_df = read_data_file("security_log.txt")
    system_df = read_data_file("system_log.txt")

    if process_df.empty:
        print("[!] No process data found.")
        return (
            pd.DataFrame(),
            application_df,
            security_df,
            system_df
        )

    report_rows = []

    for _, row in process_df.iterrows():

        pid = row["ProcessId"]
        ppid = row["ParentProcessId"]
        name = row["Name"]
        path = row["ExecutablePath"]
        command_line = row["CommandLine"]

        file_hash = hash_file(path)

        score, reasons, mapped_network = calculate_risk(
            name,
            path,
            command_line,
            pid,
            network_df
        )

        mapped_event_ids = map_event_ids_to_process(
            pid,
            application_df,
            security_df,
            system_df
        )

        level = risk_level(score)

        report_rows.append({

            "PID": pid,
            "PPID": ppid,
            "Process_Name": name,
            "Executable_Path": path,
            "SHA256": file_hash,
            "Risk_Score": score,
            "Risk_Level": level,
            "Risk_Reasons": reasons,
            "Mapped_Network_Traffic": mapped_network,
            "Mapped_Event_IDs": mapped_event_ids

        })

    return (
        pd.DataFrame(report_rows),
        application_df,
        security_df,
        system_df
    )



# EXPORT REPORTS
def export_reports(
        process_df,
        application_df,
        security_df,
        system_df
):

    process_df.to_csv(
        f"{REPORTS_FOLDER}/process_tree_report.csv",
        index=False
    )

    application_df.to_csv(
        f"{REPORTS_FOLDER}/application_log_report.csv",
        index=False
    )

    security_df.to_csv(
        f"{REPORTS_FOLDER}/security_log_report.csv",
        index=False
    )

    system_df.to_csv(
        f"{REPORTS_FOLDER}/system_log_report.csv",
        index=False
    )

    print("Reports exported.")


# MAIN FUNCTION
def lost_in_the_sauce():

    start = time.time()

    make_folders()

    run_collection_script()

    time.sleep(2)

    (
        process_df,
        application_df,
        security_df,
        system_df
    ) = analyze()

    export_reports(
        process_df,
        application_df,
        security_df,
        system_df
    )

    end = time.time()

    print(f"Finished in {round(end - start, 2)} seconds")

main_name = "lost_in_the_sauce"
if main_name == "lost_in_the_sauce":
    lost_in_the_sauce()