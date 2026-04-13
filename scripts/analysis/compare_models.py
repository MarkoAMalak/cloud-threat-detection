import csv
from collections import Counter

BASELINE_CSV = "cloudtrail_scored.csv"
BEHAVIOR_CSV = "cloudtrail_behavior_scored.csv"


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


def load_rows(path):
    with open(path, "r", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def summarize(path):
    rows = load_rows(path)
    anomalies = [r for r in rows if safe_int(r.get("is_anomaly", 0)) == 1]

    event_counter = Counter(normalize(r.get("eventName")) for r in anomalies)
    user_counter = Counter(normalize(r.get("username")) for r in anomalies)

    return {
        "total_rows": len(rows),
        "anomaly_rows": len(anomalies),
        "top_events": event_counter.most_common(10),
        "top_users": user_counter.most_common(10),
    }


def print_summary(title, summary):
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)
    print(f"Total rows    : {summary['total_rows']}")
    print(f"Anomaly rows  : {summary['anomaly_rows']}")

    print("\nTop events:")
    for i, (name, count) in enumerate(summary["top_events"], start=1):
        print(f"{i:>2}. {name} -> {count}")

    print("\nTop users:")
    for i, (name, count) in enumerate(summary["top_users"], start=1):
        print(f"{i:>2}. {name} -> {count}")


def main():
    baseline = summarize(BASELINE_CSV)
    behavior = summarize(BEHAVIOR_CSV)

    print_summary("BASELINE MODEL", baseline)
    print_summary("BEHAVIOR MODEL", behavior)

    print("\nDone.")


if __name__ == "__main__":
    main()