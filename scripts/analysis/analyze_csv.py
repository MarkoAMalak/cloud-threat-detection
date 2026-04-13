import csv
from collections import Counter

INPUT_CSV = "cloudtrail_cleaned_all_20.csv"


def safe_int(value):
    try:
        return int(str(value).strip())
    except Exception:
        return 0


def normalize(value):
    if value is None:
        return "unknown"
    value = str(value).strip()
    return value if value else "unknown"


def print_section(title):
    print("\n" + "=" * 70)
    print(title)
    print("=" * 70)


def print_top(counter, title, top_n=10):
    print_section(title)
    if not counter:
        print("No data found.")
        return

    for i, (key, count) in enumerate(counter.most_common(top_n), start=1):
        print(f"{i:>2}. {key} -> {count}")


def main():
    rows = []

    try:
        with open(INPUT_CSV, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            rows = list(reader)
    except FileNotFoundError:
        print(f"File not found: {INPUT_CSV}")
        return
    except Exception as e:
        print(f"Error reading file: {e}")
        return

    if not rows:
        print("CSV file is empty.")
        return

    columns = list(rows[0].keys())

    print_section("BASIC INFO")
    print(f"File name        : {INPUT_CSV}")
    print(f"Total rows       : {len(rows)}")
    print(f"Total columns    : {len(columns)}")

    print_section("COLUMN NAMES")
    for i, col in enumerate(columns, start=1):
        print(f"{i:>2}. {col}")

    # Counters
    event_name_counter = Counter()
    event_source_counter = Counter()
    username_counter = Counter()
    source_ip_counter = Counter()
    region_counter = Counter()
    risk_level_counter = Counter()

    # Flags / summary counts
    access_denied_count = 0
    root_count = 0
    mfa_false_count = 0
    error_count = 0
    unknown_username_count = 0
    unknown_ip_count = 0

    for row in rows:
        event_name = normalize(row.get("eventName"))
        event_source = normalize(row.get("eventSource"))
        username = normalize(row.get("username"))
        source_ip = normalize(row.get("sourceIPAddress"))
        region = normalize(row.get("awsRegion"))
        risk_level = normalize(row.get("risk_level"))

        event_name_counter[event_name] += 1
        event_source_counter[event_source] += 1
        username_counter[username] += 1
        source_ip_counter[source_ip] += 1
        region_counter[region] += 1
        risk_level_counter[risk_level] += 1

        access_denied_count += safe_int(row.get("is_access_denied", 0))
        root_count += safe_int(row.get("is_root", 0))
        mfa_false_count += safe_int(row.get("is_mfa_false", 0))
        error_count += safe_int(row.get("is_error", 0))

        if username == "unknown":
            unknown_username_count += 1
        if source_ip == "unknown":
            unknown_ip_count += 1

    print_section("SECURITY SUMMARY")
    print(f"AccessDenied events    : {access_denied_count}")
    print(f"Root events            : {root_count}")
    print(f"MFA false events       : {mfa_false_count}")
    print(f"Error events           : {error_count}")
    print(f"Unknown usernames      : {unknown_username_count}")
    print(f"Unknown source IPs     : {unknown_ip_count}")

    print_top(event_name_counter, "TOP 10 EVENT NAMES")
    print_top(event_source_counter, "TOP 10 EVENT SOURCES")
    print_top(username_counter, "TOP 10 USERNAMES")
    print_top(source_ip_counter, "TOP 10 SOURCE IP ADDRESSES")
    print_top(region_counter, "TOP 10 AWS REGIONS")
    print_top(risk_level_counter, "RISK LEVEL DISTRIBUTION", top_n=10)

    print_section("SAMPLE ROWS (FIRST 5)")
    for i, row in enumerate(rows[:5], start=1):
        print(f"\nRow {i}:")
        important_fields = [
            "eventTime",
            "eventName",
            "eventSource",
            "username",
            "sourceIPAddress",
            "awsRegion",
            "is_root",
            "is_error",
            "is_access_denied",
            "is_mfa_false",
            "risk_score",
            "risk_level",
        ]
        for field in important_fields:
            print(f"  {field:20}: {row.get(field, '')}")

    print("\nDone.")


if __name__ == "__main__":
    main()