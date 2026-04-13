import os
import csv
import gzip
import json
from glob import glob
from datetime import datetime


INPUT_FOLDER = "."
OUTPUT_CSV = "cloudtrail_cleaned_all_20.csv"


def load_json(path):
    if path.lower().endswith(".gz"):
        with gzip.open(path, "rt", encoding="utf-8") as f:
            return json.load(f)
    else:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)


def get_nested(data, *keys, default=""):
    current = data
    for key in keys:
        if not isinstance(current, dict):
            return default
        current = current.get(key)
        if current is None:
            return default
    return current


def clean_text(value, lower=False, default="unknown"):
    if value is None:
        return default
    value = str(value).strip()
    if value == "":
        return default
    if lower:
        value = value.lower()
    return value


def parse_time(event_time):
    if not event_time:
        return "", "", "", "", 0
    try:
        dt = datetime.fromisoformat(event_time.replace("Z", "+00:00"))
        date_only = dt.date().isoformat()
        hour = dt.hour
        day_of_week = dt.weekday()   # Monday=0
        month = dt.month
        is_weekend = 1 if day_of_week in [5, 6] else 0
        return date_only, hour, day_of_week, month, is_weekend
    except Exception:
        return "", "", "", "", 0


def extract_username(user_arn, session_issuer_user_name):
    if session_issuer_user_name and session_issuer_user_name != "unknown":
        return session_issuer_user_name

    if not user_arn or user_arn == "unknown":
        return "unknown"

    # examples:
    # arn:aws:iam::123456789012:user/backup
    # arn:aws:sts::123456789012:assumed-role/role-name/session-name
    try:
        last_part = user_arn.split("/")[-1].strip()
        return last_part if last_part else "unknown"
    except Exception:
        return "unknown"


def safe_flag(condition):
    return 1 if condition else 0


def flatten_record(record, source_file, record_index):
    event_time = clean_text(record.get("eventTime", ""), default="")
    date_only, hour, day_of_week, month, is_weekend = parse_time(event_time)

    event_name = clean_text(record.get("eventName", ""), default="unknown")
    event_source = clean_text(record.get("eventSource", ""), lower=True)
    event_type = clean_text(record.get("eventType", ""), default="unknown")
    source_ip = clean_text(record.get("sourceIPAddress", ""), default="unknown")
    aws_region = clean_text(record.get("awsRegion", ""), lower=True)
    user_agent = clean_text(record.get("userAgent", ""))
    recipient_account_id = clean_text(record.get("recipientAccountId", ""), default="unknown")
    error_code = clean_text(record.get("errorCode", ""), lower=True)
    error_message = clean_text(record.get("errorMessage", ""), default="")
    event_id = clean_text(record.get("eventID", ""), default="")
    request_id = clean_text(record.get("requestID", ""), default="")

    user_type = clean_text(get_nested(record, "userIdentity", "type"), lower=True)
    user_principal_id = clean_text(get_nested(record, "userIdentity", "principalId"))
    user_arn = clean_text(get_nested(record, "userIdentity", "arn"))
    user_account_id = clean_text(get_nested(record, "userIdentity", "accountId"), default="unknown")
    access_key_id = clean_text(get_nested(record, "userIdentity", "accessKeyId"), default="unknown")

    mfa_authenticated = clean_text(
        get_nested(record, "userIdentity", "sessionContext", "attributes", "mfaAuthenticated"),
        lower=True
    )

    session_creation_date = clean_text(
        get_nested(record, "userIdentity", "sessionContext", "attributes", "creationDate"),
        default=""
    )

    session_issuer_type = clean_text(
        get_nested(record, "userIdentity", "sessionContext", "sessionIssuer", "type"),
        lower=True
    )

    session_issuer_arn = clean_text(
        get_nested(record, "userIdentity", "sessionContext", "sessionIssuer", "arn")
    )

    session_issuer_user_name = clean_text(
        get_nested(record, "userIdentity", "sessionContext", "sessionIssuer", "userName")
    )

    username = extract_username(user_arn, session_issuer_user_name)

    # flags
    is_root = safe_flag(user_type == "root")
    is_error = safe_flag(error_code != "unknown")
    is_access_denied = safe_flag("accessdenied" in error_code)
    is_mfa_false = safe_flag(mfa_authenticated == "false")
    is_iam_event = safe_flag(event_source == "iam.amazonaws.com")
    is_cloudtrail_event = safe_flag(event_source == "cloudtrail.amazonaws.com")
    is_console_login = safe_flag(event_name == "ConsoleLogin")
    is_s3_event = safe_flag(event_source == "s3.amazonaws.com")
    is_ec2_event = safe_flag(event_source == "ec2.amazonaws.com")
    is_from_unknown_ip = safe_flag(source_ip == "unknown")
    is_us_east_1 = safe_flag(aws_region == "us-east-1")

    # simple risk hint
    risk_score = (
        is_root * 3 +
        is_mfa_false * 2 +
        is_access_denied * 2 +
        is_error * 1 +
        is_cloudtrail_event * 1
    )

    if risk_score >= 5:
        risk_level = "high"
    elif risk_score >= 2:
        risk_level = "medium"
    else:
        risk_level = "low"

    row = {
        "source_file": source_file,
        "record_index": record_index,
        "eventTime": event_time,
        "date_only": date_only,
        "hour": hour,
        "day_of_week": day_of_week,
        "month": month,
        "is_weekend": is_weekend,

        "eventName": event_name,
        "eventSource": event_source,
        "eventType": event_type,
        "eventID": event_id,
        "requestID": request_id,

        "sourceIPAddress": source_ip,
        "awsRegion": aws_region,
        "userAgent": user_agent,
        "recipientAccountId": recipient_account_id,

        "errorCode": error_code,
        "errorMessage": error_message,

        "userIdentity_type": user_type,
        "userIdentity_principalId": user_principal_id,
        "userIdentity_arn": user_arn,
        "userIdentity_accountId": user_account_id,
        "userIdentity_accessKeyId": access_key_id,

        "mfaAuthenticated": mfa_authenticated,
        "sessionCreationDate": session_creation_date,
        "sessionIssuer_type": session_issuer_type,
        "sessionIssuer_arn": session_issuer_arn,
        "sessionIssuer_userName": session_issuer_user_name,

        "username": username,

        "is_root": is_root,
        "is_error": is_error,
        "is_access_denied": is_access_denied,
        "is_mfa_false": is_mfa_false,
        "is_iam_event": is_iam_event,
        "is_cloudtrail_event": is_cloudtrail_event,
        "is_console_login": is_console_login,
        "is_s3_event": is_s3_event,
        "is_ec2_event": is_ec2_event,
        "is_from_unknown_ip": is_from_unknown_ip,
        "is_us_east_1": is_us_east_1,

        "risk_score": risk_score,
        "risk_level": risk_level,
    }

    return row


def get_dedup_key(row):
    # prefer unique eventID if available
    if row["eventID"]:
        return row["eventID"]

    # fallback composite key
    return "|".join([
        row["eventTime"],
        row["eventName"],
        row["eventSource"],
        row["sourceIPAddress"],
        row["userIdentity_arn"],
        row["awsRegion"],
        row["requestID"],
    ])


def main():
    patterns = [
        os.path.join(INPUT_FOLDER, "*.json"),
        os.path.join(INPUT_FOLDER, "*.json.gz"),
    ]

    files = []
    for pattern in patterns:
        files.extend(glob(pattern))

    files = sorted(files)

    if not files:
        print(f"No JSON or JSON.GZ files found in folder: {INPUT_FOLDER}")
        return

    all_rows = []
    seen = set()
    total_records = 0
    duplicates_removed = 0
    skipped_bad_rows = 0

    for file_num, file_path in enumerate(files, start=1):
        print(f"[{file_num}/{len(files)}] Processing: {file_path}")
        try:
            data = load_json(file_path)
            records = data.get("Records", [])
            total_records += len(records)

            for i, record in enumerate(records, start=1):
                try:
                    row = flatten_record(record, os.path.basename(file_path), i)

                    # skip rows missing both event time and event name
                    if not row["eventTime"] and row["eventName"] == "unknown":
                        skipped_bad_rows += 1
                        continue

                    dedup_key = get_dedup_key(row)
                    if dedup_key in seen:
                        duplicates_removed += 1
                        continue

                    seen.add(dedup_key)
                    all_rows.append(row)

                except Exception:
                    skipped_bad_rows += 1

            print(f"    -> Added cleaned records from {len(records)} raw events")

        except Exception as e:
            print(f"    -> ERROR in {file_path}: {e}")

    if not all_rows:
        print("No rows extracted.")
        return

    fieldnames = list(all_rows[0].keys())

    with open(OUTPUT_CSV, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(all_rows)

    print("\nDone.")
    print(f"Raw records found     : {total_records}")
    print(f"Rows written          : {len(all_rows)}")
    print(f"Duplicates removed    : {duplicates_removed}")
    print(f"Skipped bad rows      : {skipped_bad_rows}")
    print(f"Output file           : {OUTPUT_CSV}")


if __name__ == "__main__":
    main()