
# Keylogger Detector & Remediation

The Keylogger Detector & Remediation project is a Python-based security tool designed to detect, report, and optionally remediate potential keylogger activity on Windows systems. The tool scans running processes, startup registry entries, scheduled tasks, and network connections using heuristic analysis to identify suspicious programs.

# Key Features

- Cross-platform process enumeration using psutil (Windows-focused features include registry and scheduled task analysis).

- Heuristic detection based on executable path, name hints, and small size in user directories.

- Network connection checks for processes that may transmit keystroke data.

- Safe quarantine and optional process termination.

- Timestamped reporting with easy-to-read summary.

# Target Users

- Security enthusiasts learning about keylogger detection.

- IT administrators performing system audits.

- Developers and hobbyists exploring Windows security scripting.


## Installation

1️⃣ Prerequisites

- Windows OS (registry and scheduled task scanning are Windows-only).

- Python 3.8+ installed and added to your PATH.

- Recommended: Run VS Code or Terminal as Administrator for full process access.

2️⃣ Clone the Repository

Open your terminal (or cmd) and run:

```bash
  (https://github.com/sivaprasathl57-ctrl/Keylogger-Detector-Remediation.git)
  cd keylogger-detector
```
3️⃣ Install Dependencies

Install required Python packages using pip:
``` bash
pip install psutil
```
Optional: create a requirements.txt with:
```bash
psutil    
```
Then install with:
```bash

pip install -r requirements.txt
```
4️⃣ Run the Script
```bash
python keylogger_detector_remediate.py
```


- The program will scan for suspicious processes, startup keys, and scheduled tasks.

- Administrator privileges are recommended to detect all system processes.

6️⃣ Notes

- The tool uses heuristics; some normal applications (e.g., VS Code, Python) may be flagged.

- Quarantined files are read-only to prevent execution.

- Always verify findings before deleting or terminating processes.
## Screenshots

- Prograss
![Screenshot 2025-10-01 210425](https://github.com/user-attachments/assets/a8e69a65-ee56-4bfd-a8c9-da5721d6d559)


![Screenshot 2025-10-01 210551](https://github.com/user-attachments/assets/1fa77a07-435d-4a86-8d1a-ee21cf1bdc2e)





  
## Output


![output 1](https://github.com/user-attachments/assets/16823b63-fa45-40bc-8710-a5ed993165db)


![output 2](https://github.com/user-attachments/assets/7399e3a0-bb48-4a29-b3e4-b3a7be4ddd29)

![output 3](https://github.com/user-attachments/assets/ea165118-8ba0-4f62-a5f8-104ed003d58b)

![output 4](https://github.com/user-attachments/assets/5aa9cfbb-be78-497f-8b48-ab3830e2b256)

