from analyzer import analyze
from report import print_report
from remediation import remediate

if __name__ == "__main__":
    report = analyze()
    print_report(report)

    if report['findings']:
        print("\nFound suspicious processes. Running remediation steps...")
        remediate(report)
    else:
        print("\nNo suspicious processes detected by heuristic scan.")
