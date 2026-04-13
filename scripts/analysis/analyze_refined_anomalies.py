import csv
from collections import Counter

INPUT_CSV = "cloudtrail_behavior_refined_scored.csv"
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
    source_counter = Counter()
    priority_counter = Counter()

    human_count = 0
    automation_count = 0

    for row in anomalies:
        event_counter[normalize(row.get("eventName"))] += 1
        user_counter[normalize(row.get("username"))] += 1
        ip_counter[normalize(row.get("sourceIPAddress"))] += 1
        source_counter[normalize(row.get("eventSource"))] += 1
        priority_counter[normalize(row.get("review_priority"))] += 1
        human_count += safe_int(row.get("is_human_activity", 0))
        automation_count += safe_int(row.get("is_automation_activity", 0))

    print_section("ANOMALY SUMMARY")
    print(f"Human activity anomalies      : {human_count}")
    print(f"Automation activity anomalies : {automation_count}")

    print_section("TOP ANOMALOUS EVENT NAMES")
    for i, (k, v) in enumerate(event_counter.most_common(TOP_N), start=1):
        print(f"{i:>2}. {k} -> {v}")

    print_section("TOP ANOMALOUS USERNAMES")
    for i, (k, v) in enumerate(user_counter.most_common(TOP_N), start=1):
        print(f"{i:>2}. {k} -> {v}")

    print_section("TOP ANOMALOUS SOURCE IPs")
    for i, (k, v) in enumerate(ip_counter.most_common(TOP_N), start=1):
        print(f"{i:>2}. {k} -> {v}")

    print_section("TOP ANOMALOUS EVENT SOURCES")
    for i, (k, v) in enumerate(source_counter.most_common(TOP_N), start=1):
        print(f"{i:>2}. {k} -> {v}")

    print_section("REVIEW PRIORITY DISTRIBUTION")
    for i, (k, v) in enumerate(priority_counter.most_common(), start=1):
        print(f"{i:>2}. {k} -> {v}")

    anomalies_sorted = sorted(anomalies, key=lambda x: safe_float(x.get("anomaly_score", 0.0)))

    print_section("TOP 20 MOST ANOMALOUS ROWS")
    for i, row in enumerate(anomalies_sorted[:TOP_REVIEW], start=1):
        print(f"\n[{i}]")
        print(f"eventTime             : {normalize(row.get('eventTime'))}")
        print(f"eventName             : {normalize(row.get('eventName'))}")
        print(f"eventSource           : {normalize(row.get('eventSource'))}")
        print(f"username              : {normalize(row.get('username'))}")
        print(f"sourceIPAddress       : {normalize(row.get('sourceIPAddress'))}")
        print(f"awsRegion             : {normalize(row.get('awsRegion'))}")
        print(f"review_priority       : {normalize(row.get('review_priority'))}")
        print(f"is_human_activity     : {normalize(row.get('is_human_activity'))}")
        print(f"is_automation_activity: {normalize(row.get('is_automation_activity'))}")
        print(f"refined_risk_score    : {normalize(row.get('refined_risk_score'))}")
        print(f"anomaly_score         : {safe_float(row.get('anomaly_score')):.6f}")

    print("\nDone.")


if __name__ == "__main__":
    main()