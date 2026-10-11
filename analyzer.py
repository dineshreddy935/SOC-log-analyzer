
from collections import Counter
from pathlib import Path
import re

LOG_FILE = Path(__file__).with_name("sample_logs.txt")

FAILED_LOGIN_PATTERN = re.compile(
    r"\[FAILED LOGIN\].*?\bip=(\d{1,3}(?:\.\d{1,3}){3})"
)


def analyze_logs():
    if not LOG_FILE.exists():
        print("Error: sample_logs.txt was not found.")
        return

    failed_logins = Counter()
    total_events = 0

    with LOG_FILE.open("r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()

            if not line:
                continue

            total_events += 1
            match = FAILED_LOGIN_PATTERN.search(line)

            if match:
                failed_logins[match.group(1)] += 1

    print("=" * 40)
    print("SOC LOG ANALYZER")
    print("=" * 40)
    print(f"Total events: {total_events}")
    print(f"Failed logins: {sum(failed_logins.values())}")

    print("\nFailed login attempts by IP:")

    if not failed_logins:
        print("No failed login events found.")
        return

    for ip, count in failed_logins.most_common():
        status = "SUSPICIOUS" if count >= 3 else "Below threshold"
        print(f"{ip}: {count} attempts - {status}")

    print("\nAnalysis complete.")
    print("Repeated failures do not prove an attack.")


if __name__ == "__main__":
    analyze_logs()
