import csv
from collections import Counter

INPUT_CSV = "cloudtrail_behavior_scored.csv"
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


def load_rows(path):
    with open(path, "r", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def print_top(counter, title, top_n=10):
    print_section(title)
    for i, (key, count) in enumerate(counter.most_common(top_n), start=1):
        print(f"{i:>2}. {key} -> {count}")


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
    rows = load_rows(INPUT_CSV)
    anomalies = [r for r in rows if safe_int(r.get("is_anomaly", 0)) == 1]

    print_section("BASIC INFO")
    print(f"Input file      : {INPUT_CSV}")
    print(f"Total rows      : {len(rows)}")
    print(f"Anomaly rows    : {len(anomalies)}")

    if not anomalies:
        print("No anomalies found.")
        return

    event_counter = Counter()
    user_counter = Counter()
    ip_counter = Counter()
    region_counter = Counter()
    source_counter = Counter()

    for row in anomalies:
        event_counter[normalize(row.get("eventName"))] += 1
        user_counter[normalize(row.get("username"))] += 1
        ip_counter[normalize(row.get("sourceIPAddress"))] += 1
        region_counter[normalize(row.get("awsRegion"))] += 1
        source_counter[normalize(row.get("eventSource"))] += 1

    print_top(event_counter, "TOP ANOMALOUS EVENT NAMES", TOP_N)
    print_top(user_counter, "TOP ANOMALOUS USERNAMES", TOP_N)
    print_top(ip_counter, "TOP ANOMALOUS SOURCE IPs", TOP_N)
    print_top(region_counter, "TOP ANOMALOUS REGIONS", TOP_N)
    print_top(source_counter, "TOP ANOMALOUS EVENT SOURCES", TOP_N)

    anomalies_sorted = sorted(anomalies, key=lambda x: safe_float(x.get("anomaly_score", 0.0)))

    print_section("TOP 20 MOST ANOMALOUS ROWS")
    for i, row in enumerate(anomalies_sorted[:TOP_REVIEW], start=1):
        print(f"\n[{i}]")
        print(f"eventTime           : {normalize(row.get('eventTime'))}")
        print(f"eventName           : {normalize(row.get('eventName'))}")
        print(f"eventSource         : {normalize(row.get('eventSource'))}")
        print(f"username            : {normalize(row.get('username'))}")
        print(f"sourceIPAddress     : {normalize(row.get('sourceIPAddress'))}")
        print(f"awsRegion           : {normalize(row.get('awsRegion'))}")
        print(f"risk_score          : {normalize(row.get('risk_score'))}")
        print(f"behavior_risk_score : {normalize(row.get('behavior_risk_score'))}")
        print(f"anomaly_score       : {safe_float(row.get('anomaly_score')):.6f}")

    seen = set()
    unique_rows = []
    for row in anomalies_sorted:
        key = get_dedup_key(row)
        if key in seen:
            continue
        seen.add(key)
        unique_rows.append(row)

    print_section("DEDUPLICATED ANOMALIES")
    print(f"Original anomaly rows : {len(anomalies_sorted)}")
    print(f"Unique anomaly rows   : {len(unique_rows)}")
    print(f"Duplicates removed    : {len(anomalies_sorted) - len(unique_rows)}")

    print_section("TOP 20 UNIQUE ANOMALIES")
    for i, row in enumerate(unique_rows[:TOP_REVIEW], start=1):
        print(f"\n[{i}]")
        print(f"eventTime           : {normalize(row.get('eventTime'))}")
        print(f"eventName           : {normalize(row.get('eventName'))}")
        print(f"eventSource         : {normalize(row.get('eventSource'))}")
        print(f"username            : {normalize(row.get('username'))}")
        print(f"sourceIPAddress     : {normalize(row.get('sourceIPAddress'))}")
        print(f"awsRegion           : {normalize(row.get('awsRegion'))}")
        print(f"risk_score          : {normalize(row.get('risk_score'))}")
        print(f"behavior_risk_score : {normalize(row.get('behavior_risk_score'))}")
        print(f"anomaly_score       : {safe_float(row.get('anomaly_score')):.6f}")

    print("\nDone.")


if __name__ == "__main__":
    main()