from datetime import datetime

THRESHOLD = 5
WINDOW_SECONDS = 60


def parse_logs(logfile):
    fails_by_ip = {}

    with open(logfile, "r", encoding="utf-8") as file:
        for line in file:
            line = line.strip()
            if not line:
                continue

            parts = line.split()
            if len(parts) < 4:
                continue

            event = parts[2]
            if event != "LOGIN_FAIL":
                continue

            ip = parts[3]
            ts = datetime.strptime(parts[0] + " " + parts[1],
                                   "%Y-%m-%d %H:%M:%S")

            if ip not in fails_by_ip:
                fails_by_ip[ip] = []

            fails_by_ip[ip].append(ts)

    return fails_by_ip


def detect_bruteforce(fails_by_ip):
    alerts = []

    for ip, times in fails_by_ip.items():
        times.sort()

        for i in range(len(times) - THRESHOLD + 1):
            start = times[i]
            end = times[i + THRESHOLD - 1]

            if (end - start).total_seconds() <= WINDOW_SECONDS:
                alerts.append((ip, start, end))
                break

    return alerts


def main():
    logfile = "sample_logs.txt"

    fails_by_ip = parse_logs(logfile)
    alerts = detect_bruteforce(fails_by_ip)

    print("=== Brute-force control ===")
    if not alerts:
        print("No brute-force attempts detected.")
    else:
        for ip, start, end in alerts:
            print(f"{ip} -> 5 tries from {start} until {end}")

    print("\n=== Failed login statistics ===")
    total_fails = 0
    for ip, times in fails_by_ip.items():
        count = len(times)
        total_fails += count
        print(f"{ip}: {count} failed login attempts")

    print(f"\nTotal failed login attempts: {total_fails}")


if __name__ == "__main__":
    main()

