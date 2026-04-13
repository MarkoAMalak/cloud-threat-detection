import csv
from collections import Counter

INPUT_CSV = "cloudtrail_scored.csv"
TOP_N = 10
TOP_REVIEW = 20


def normalize(value, default="unknown"):
    if value is None:
        return default
    value = str(value).strip()
    return value if value else default


def safe_int(value):
    try:
        return int(str(value).strip())
    except Exception:
        return 0


def safe_float(value):
    try:
        return float(str(value).strip())
    except Exception:
        return 0.0


def print_section(title):
    print("\n" + "=" * 75)
    print(title)
    print("=" * 75)


def print_top(counter, title, top_n=10):
    print_section(title)
    if not counter:
        print("No data found.")
        return

    for i, (key, count) in enumerate(counter.most_common(top_n), start=1):
        print(f"{i:>2}. {key} -> {count}")


def load_rows(path):
    with open(path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        return list(reader)


def get_dedup_key(row):
    return (
        normalize(row.get("eventTime")),
        normalize(row.get("eventName")),
        normalize(row.get("eventSource")),
        normalize(row.get("username")),
        normalize(row.get("sourceIPAddress")),
        normalize(row.get("awsRegion")),
    )


def main():
    try:
        rows = load_rows(INPUT_CSV)
    except FileNotFoundError:
        print(f"File not found: {INPUT_CSV}")
        return
    except Exception as e:
        print(f"Error reading file: {e}")
        return

    if not rows:
        print("CSV file is empty.")
        return

    print_section("BASIC INFO")
    print(f"Input file        : {INPUT_CSV}")
    print(f"Total rows        : {len(rows)}")

    anomalies = [row for row in rows if safe_int(row.get("is_anomaly", 0)) == 1]

    print(f"Anomaly rows      : {len(anomalies)}")
    if not anomalies:
        print("No anomalies found.")
        return

    anomaly_percent = (len(anomalies) / len(rows)) * 100
    print(f"Anomaly percent   : {anomaly_percent:.2f}%")

    # Counters
    event_counter = Counter()
    source_counter = Counter()
    username_counter = Counter()
    ip_counter = Counter()
    region_counter = Counter()
    risk_counter = Counter()

    root_count = 0
    access_denied_count = 0
    mfa_false_count = 0
    error_count = 0

    for row in anomalies:
        event_counter[normalize(row.get("eventName"))] += 1
        source_counter[normalize(row.get("eventSource"))] += 1
        username_counter[normalize(row.get("username"))] += 1
        ip_counter[normalize(row.get("sourceIPAddress"))] += 1
        region_counter[normalize(row.get("awsRegion"))] += 1
        risk_counter[normalize(row.get("risk_level"))] += 1

        root_count += safe_int(row.get("is_root", 0))
        access_denied_count += safe_int(row.get("is_access_denied", 0))
        mfa_false_count += safe_int(row.get("is_mfa_false", 0))
        error_count += safe_int(row.get("is_error", 0))

    print_section("ANOMALY SECURITY SUMMARY")
    print(f"Root anomalies            : {root_count}")
    print(f"AccessDenied anomalies    : {access_denied_count}")
    print(f"MFA false anomalies       : {mfa_false_count}")
    print(f"Error anomalies           : {error_count}")

    print_top(event_counter, "TOP ANOMALOUS EVENT NAMES", TOP_N)
    print_top(source_counter, "TOP ANOMALOUS EVENT SOURCES", TOP_N)
    print_top(username_counter, "TOP ANOMALOUS USERNAMES", TOP_N)
    print_top(ip_counter, "TOP ANOMALOUS SOURCE IPs", TOP_N)
    print_top(region_counter, "TOP ANOMALOUS REGIONS", TOP_N)
    print_top(risk_counter, "ANOMALY RISK LEVEL DISTRIBUTION", TOP_N)

    # Sort anomalies by most anomalous first
    anomalies_sorted = sorted(anomalies, key=lambda x: safe_float(x.get("anomaly_score", 0.0)))

    print_section("TOP 20 MOST ANOMALOUS ROWS")
    for i, row in enumerate(anomalies_sorted[:TOP_REVIEW], start=1):
        print(f"\n[{i}]")
        print(f"eventTime       : {normalize(row.get('eventTime'))}")
        print(f"eventName       : {normalize(row.get('eventName'))}")
        print(f"eventSource     : {normalize(row.get('eventSource'))}")
        print(f"username        : {normalize(row.get('username'))}")
        print(f"sourceIPAddress : {normalize(row.get('sourceIPAddress'))}")
        print(f"awsRegion       : {normalize(row.get('awsRegion'))}")
        print(f"is_root         : {safe_int(row.get('is_root'))}")
        print(f"is_error        : {safe_int(row.get('is_error'))}")
        print(f"is_access_denied: {safe_int(row.get('is_access_denied'))}")
        print(f"is_mfa_false    : {safe_int(row.get('is_mfa_false'))}")
        print(f"risk_level      : {normalize(row.get('risk_level'))}")
        print(f"anomaly_score   : {safe_float(row.get('anomaly_score')):.6f}")

    # Deduplicate
    unique_anomalies = []
    seen = set()

    for row in anomalies_sorted:
        key = get_dedup_key(row)
        if key in seen:
            continue
        seen.add(key)
        unique_anomalies.append(row)

    print_section("DEDUPLICATED ANOMALIES")
    print(f"Original anomaly rows     : {len(anomalies_sorted)}")
    print(f"Unique anomaly rows       : {len(unique_anomalies)}")
    print(f"Duplicates removed        : {len(anomalies_sorted) - len(unique_anomalies)}")

    print_section("TOP 20 UNIQUE ANOMALIES")
    for i, row in enumerate(unique_anomalies[:TOP_REVIEW], start=1):
        print(f"\n[{i}]")
        print(f"eventTime       : {normalize(row.get('eventTime'))}")
        print(f"eventName       : {normalize(row.get('eventName'))}")
        print(f"eventSource     : {normalize(row.get('eventSource'))}")
        print(f"username        : {normalize(row.get('username'))}")
        print(f"sourceIPAddress : {normalize(row.get('sourceIPAddress'))}")
        print(f"awsRegion       : {normalize(row.get('awsRegion'))}")
        print(f"risk_level      : {normalize(row.get('risk_level'))}")
        print(f"anomaly_score   : {safe_float(row.get('anomaly_score')):.6f}")

    print("\nDone.")


if __name__ == "__main__":
    main()