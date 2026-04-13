import csv
import ipaddress
from collections import Counter

INPUT_CSV = "cloudtrail_cleaned_all_20.csv"
OUTPUT_CSV = "model_input.csv"

# هنحتفظ فقط بأكثر القيم شيوعًا، والباقي يتحول إلى "other"
TOP_EVENT_NAMES = 40
TOP_EVENT_SOURCES = 20
TOP_USERNAMES = 30
TOP_REGIONS = 20


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


def is_real_ip(value):
    try:
        ipaddress.ip_address(value)
        return 1
    except Exception:
        return 0


def is_aws_service_name(value):
    value = normalize(value).lower()
    return 1 if value.endswith(".amazonaws.com") else 0


def load_rows(path):
    with open(path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        return list(reader)


def get_top_values(rows, column_name, top_n):
    counter = Counter()
    for row in rows:
        val = normalize(row.get(column_name))
        counter[val] += 1
    return set(k for k, _ in counter.most_common(top_n))


def bucket_value(value, allowed_values):
    value = normalize(value)
    if value in allowed_values:
        return value
    return "other"


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
        print("Input CSV is empty.")
        return

    print(f"Loaded rows: {len(rows)}")

    # نحدد أشهر القيم حتى لا يصبح الـ encoding ضخمًا بعدين
    top_event_names = get_top_values(rows, "eventName", TOP_EVENT_NAMES)
    top_event_sources = get_top_values(rows, "eventSource", TOP_EVENT_SOURCES)
    top_usernames = get_top_values(rows, "username", TOP_USERNAMES)
    top_regions = get_top_values(rows, "awsRegion", TOP_REGIONS)

    output_rows = []

    for row in rows:
        event_name = bucket_value(row.get("eventName"), top_event_names)
        event_source = bucket_value(row.get("eventSource"), top_event_sources)
        username = bucket_value(row.get("username"), top_usernames)
        aws_region = bucket_value(row.get("awsRegion"), top_regions)

        source_ip = normalize(row.get("sourceIPAddress"))
        user_agent = normalize(row.get("userAgent")).lower()

        # features إضافية مفيدة
        source_ip_is_real = is_real_ip(source_ip)
        source_ip_is_service = is_aws_service_name(source_ip)
        user_agent_is_console = 1 if "console" in user_agent else 0
        user_agent_is_cli = 1 if "aws-cli" in user_agent else 0
        user_agent_is_sdk = 1 if ("boto" in user_agent or "botocore" in user_agent or "aws-sdk" in user_agent) else 0

        cleaned = {
            # categorical columns
            "eventName": event_name,
            "eventSource": event_source,
            "username": username,
            "awsRegion": aws_region,

            # numeric / binary columns
            "hour": safe_int(row.get("hour")),
            "day_of_week": safe_int(row.get("day_of_week")),
            "month": safe_int(row.get("month")),
            "is_weekend": safe_int(row.get("is_weekend")),
            "is_root": safe_int(row.get("is_root")),
            "is_error": safe_int(row.get("is_error")),
            "is_access_denied": safe_int(row.get("is_access_denied")),
            "is_mfa_false": safe_int(row.get("is_mfa_false")),
            "is_iam_event": safe_int(row.get("is_iam_event")),
            "is_cloudtrail_event": safe_int(row.get("is_cloudtrail_event")),
            "is_console_login": safe_int(row.get("is_console_login")),
            "is_s3_event": safe_int(row.get("is_s3_event")),
            "is_ec2_event": safe_int(row.get("is_ec2_event")),
            "is_from_unknown_ip": safe_int(row.get("is_from_unknown_ip")),
            "is_us_east_1": safe_int(row.get("is_us_east_1")),
            "risk_score": safe_int(row.get("risk_score")),

            # added engineered features
            "source_ip_is_real": source_ip_is_real,
            "source_ip_is_service": source_ip_is_service,
            "user_agent_is_console": user_agent_is_console,
            "user_agent_is_cli": user_agent_is_cli,
            "user_agent_is_sdk": user_agent_is_sdk,

            # useful raw columns to keep for review later
            "eventTime": normalize(row.get("eventTime")),
            "sourceIPAddress": source_ip,
            "risk_level": normalize(row.get("risk_level")),
        }

        output_rows.append(cleaned)

    fieldnames = list(output_rows[0].keys())

    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(output_rows)

    print(f"Done. Wrote {len(output_rows)} rows to {OUTPUT_CSV}")
    print("\nKept top categories only:")
    print(f"- eventName   : top {TOP_EVENT_NAMES}")
    print(f"- eventSource : top {TOP_EVENT_SOURCES}")
    print(f"- username    : top {TOP_USERNAMES}")
    print(f"- awsRegion   : top {TOP_REGIONS}")


if __name__ == "__main__":
    main()