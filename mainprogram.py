import os
import shutil
import sys
import time
import hashlib
import psutil
import winreg
import subprocess
from datetime import datetime


QUARANTINE_DIR = r"C:\quarantine_keylogger_detector"
SUSPICIOUS_PATH_HINTS = [os.environ.get("TEMP", r"C:\Windows\Temp"), os.path.join(os.environ['USERPROFILE'], "AppData")]
SUSPICIOUS_NAMES = ["keylogger", "keylog", "logkeys", "klg", "kblogger"]  # heuristic substrings
SAFE_SYSTEM_DIRS = [r"C:\Windows", r"C:\Windows\System32", r"C:\Program Files", r"C:\Program Files (x86)"]

os.makedirs(QUARANTINE_DIR, exist_ok=True)

def hash_file(path, algo="sha256"):
    h = hashlib.new(algo)
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()

def is_suspicious_path(path):
    path = (path or "").lower()
    for d in SAFE_SYSTEM_DIRS:
        if path.startswith(d.lower()):
            return False
    for hint in SUSPICIOUS_PATH_HINTS:
        if hint and hint.lower() in path:
            return True
    return False

def name_matches_hint(name):
    n = (name or "").lower()
    for s in SUSPICIOUS_NAMES:
        if s in n:
            return True
    return False

def enumerate_processes():
    procs = []
    for p in psutil.process_iter(['pid','name','exe','cmdline','username']):
        try:
            info = p.info
            exe = info.get('exe') or ""
            cmdline = " ".join(info.get('cmdline') or [])
            procs.append({
                "pid": info['pid'],
                "name": info.get('name'),
                "exe": exe,
                "cmdline": cmdline,
                "username": info.get('username')
            })
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return procs

def process_network_connections(pid):
    try:
        p = psutil.Process(pid)
        conns = p.connections(kind='inet')
        return [f"{c.laddr}->{c.raddr} ({c.status})" for c in conns if c.raddr]
    except Exception:
        return []

def list_run_keys():
    keys = []
    run_paths = [
        (winreg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"),
    ]
    for hive, path in run_paths:
        try:
            with winreg.OpenKey(hive, path) as k:
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(k, i)
                        keys.append({"hive": hive, "path": path, "name": name, "value": value})
                        i += 1
                    except OSError:
                        break
        except FileNotFoundError:
            continue
    return keys

def list_scheduled_tasks():
    tasks = []
    try:
        out = subprocess.check_output(["schtasks", "/Query", "/FO", "CSV", "/V"], stderr=subprocess.DEVNULL, text=True, encoding='utf-8', errors='ignore')
        for line in out.splitlines()[1:]:
            parts = [p.strip('"') for p in line.split('","')]
            if len(parts) >= 9:
                tasks.append({
                    "taskname": parts[0],
                    "next_run_time": parts[1],
                    "status": parts[2],
                    "task_to_run": parts[8]
                })
    except Exception:
        pass
    return tasks

def quarantine_file(path):
    if not os.path.exists(path):
        return False, "file not found"
    basename = os.path.basename(path)
    ts = datetime.utcnow().strftime("%Y%m%dT%H%M%SZ")
    dest = os.path.join(QUARANTINE_DIR, f"{ts}_{basename}")
    try:
        shutil.copy2(path, dest)
        os.chmod(dest, 0o444)  
        return True, dest
    except Exception as e:
        return False, str(e)
def remove_registry_run_entry(hive, path, name):
    try:
        with winreg.OpenKey(hive, path, 0, winreg.KEY_SET_VALUE) as k:
            winreg.DeleteValue(k, name)
        return True, None
    except Exception as e:
        return False, str(e)

def delete_schtask(taskname):
    try:
        subprocess.check_output(["schtasks", "/Delete", "/TN", taskname, "/F"], stderr=subprocess.DEVNULL)
        return True, None
    except Exception as e:
        return False, str(e)

def kill_process(pid):
    try:
        p = psutil.Process(pid)
        p.terminate()
        try:
            p.wait(timeout=5)
            return True, "terminated"
        except psutil.TimeoutExpired:
            p.kill()
            p.wait(timeout=5)
            return True, "killed"
    except Exception as e:
        return False, str(e)

def analyze():
    findings = []
    procs = enumerate_processes()
    run_keys = list_run_keys()
    tasks = list_scheduled_tasks()

    for pr in procs:
        pid = pr['pid']
        name = pr['name'] or ""
        exe = pr['exe'] or ""
        cmdline = pr['cmdline'] or ""

        suspicious = False
        reasons = []

        if is_suspicious_path(exe):
            suspicious = True
            reasons.append(f"exe path suspicious: {exe}")

        if name_matches_hint(name) or name_matches_hint(cmdline) or name_matches_hint(exe):
            suspicious = True
            reasons.append("name or cmdline contains keyword hint")

        net = process_network_connections(pid)
        if net:
            reasons.append(f"network connections: {net[:3]}")

        try:
            if exe and os.path.exists(exe):
                size = os.path.getsize(exe)
                if size < 200_000 and is_suspicious_path(exe):
                    suspicious = True
                    reasons.append(f"small executable in suspicious path ({size} bytes)")
        except Exception:
            pass

        if suspicious:
            findings.append({
                "pid": pid,
                "name": name,
                "exe": exe,
                "cmdline": cmdline,
                "reasons": reasons
            })

    return {
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "findings": findings,
        "run_keys": run_keys,
        "scheduled_tasks": tasks
    }

def print_report(r):
    print("=== KEYLOGGER DETECTOR REPORT ===")
    print("Timestamp:", r['timestamp'])
    print("\n-- Suspicious processes --")
    for f in r['findings']:
        print(f"PID={f['pid']} NAME={f['name']} EXE={f['exe']}")
        for rr in f['reasons']:
            print("  -", rr)
    print("\n-- Run keys --")
    for k in r['run_keys'][:40]:
        print(f" {k['path']}\\{k['name']} = {k['value']}")
    print("\n-- Scheduled tasks (sample) --")
    for t in r['scheduled_tasks'][:40]:
        print(f" {t['taskname']} -> {t['task_to_run']}")

if __name__ == "__main__":
    if os.name != 'nt':
        print("This script is Windows-focused. It will run process checks cross-platform but registry/schtasks are Windows-only.")
    report = analyze()
    print_report(report)
    if report['findings']:
        print("\nFound suspicious processes. Example remediation actions will be printed.")
        for f in report['findings']:
            pid = f['pid']
            exe = f['exe']
            print(f"\n>> PID {pid} ({f['name']})")
            if exe and os.path.exists(exe):
                ok, dest = quarantine_file(exe)
                print("Quarantine:", ok, dest)
            ok, msg = kill_process(pid)
            print("Kill process:", ok, msg)

        print("\nTo remove a Run key programmatically, use remove_registry_run_entry(hive, path, name).")
        print("To delete scheduled task programmatically, use delete_schtask(taskname).")
    else:
        print("\nNo suspicious processes detected by heuristic scan.")

