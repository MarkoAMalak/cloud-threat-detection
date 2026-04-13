import pandas as pd

INPUT_CSV = "behavior_model_input.csv"
OUTPUT_CSV = "behavior_model_input_refined.csv"


def normalize_text(series):
    return series.fillna("unknown").astype(str).str.strip()


def is_service_ip(value: str) -> int:
    value = str(value).strip().lower()
    if value == "aws internal":
        return 1
    if value.endswith(".amazonaws.com"):
        return 1
    return 0


def is_service_user(username: str) -> int:
    u = str(username).strip().lower()

    # common service / automation identities
    if u.startswith("awsservicerole"):
        return 1
    if u.startswith("aws:"):
        return 1
    if "service-role" in u:
        return 1
    if "config-role" in u:
        return 1
    if "cloudtrail" in u and "role" in u:
        return 1
    if "organizations" in u and "role" in u:
        return 1
    if u in {
        "awsserviceroleforsupport",
        "awsserviceroleforcloudtrail",
        "awsservicerolefororganizations",
    }:
        return 1

    return 0


def is_likely_human_user(username: str) -> int:
    u = str(username).strip().lower()

    if u == "unknown":
        return 0
    if u.startswith("arn:aws:iam::") and ":root" in u:
        return 1
    if u.startswith("arn:aws:iam::") and ":user/" in u:
        return 1
    if u.startswith("arn:aws:sts::") and "assumed-role" in u:
        return 1

    # simple usernames like backup, flaws, level6, etc.
    if "/" not in u and ":" not in u and ".amazonaws.com" not in u and not u.startswith("aws"):
        return 1

    return 0


def main():
    print("Loading behavior_model_input.csv ...")
    df = pd.read_csv(INPUT_CSV)

    print(f"Rows loaded: {len(df)}")

    text_cols = ["username", "sourceIPAddress", "eventName", "eventSource", "awsRegion", "risk_level"]
    for col in text_cols:
        df[col] = normalize_text(df[col])

    print("Building service-awareness features ...")

    df["is_internal_service_ip"] = df["sourceIPAddress"].apply(is_service_ip).astype(int)
    df["is_service_user"] = df["username"].apply(is_service_user).astype(int)
    df["is_human_user"] = df["username"].apply(is_likely_human_user).astype(int)

    # combined logic
    df["is_automation_activity"] = (
        (df["is_internal_service_ip"] == 1) |
        (df["is_service_user"] == 1) |
        (df["source_ip_is_service"] == 1)
    ).astype(int)

    df["is_human_activity"] = (
        (df["is_human_user"] == 1) &
        (df["is_automation_activity"] == 0)
    ).astype(int)

    # helpful flags
    df["is_root_human_activity"] = (
        (df["is_root"] == 1) &
        (df["is_human_activity"] == 1)
    ).astype(int)

    df["is_suspicious_access_denied_human"] = (
        (df["is_access_denied"] == 1) &
        (df["is_human_activity"] == 1)
    ).astype(int)

    # refined risk score
    df["refined_risk_score"] = (
        df["risk_score"]
        + df["behavior_risk_score"]
        + df["is_root_human_activity"] * 2
        + df["is_suspicious_access_denied_human"] * 2
        - df["is_automation_activity"] * 2
    )

    # optional filter label for later dashboard / review
    df["review_priority"] = "medium"
    df.loc[df["refined_risk_score"] >= 6, "review_priority"] = "high"
    df.loc[df["refined_risk_score"] <= 1, "review_priority"] = "low"

    print("Saving refined dataset ...")
    df.to_csv(OUTPUT_CSV, index=False)

    print("\nDone.")
    print(f"Output file: {OUTPUT_CSV}")
    print(f"Rows saved : {len(df)}")
    print("\nNew columns added:")
    print("- is_internal_service_ip")
    print("- is_service_user")
    print("- is_human_user")
    print("- is_automation_activity")
    print("- is_human_activity")
    print("- is_root_human_activity")
    print("- is_suspicious_access_denied_human")
    print("- refined_risk_score")
    print("- review_priority")

    print("\nQuick summary:")
    print(f"Automation activity rows : {int(df['is_automation_activity'].sum())}")
    print(f"Human activity rows      : {int(df['is_human_activity'].sum())}")


if __name__ == "__main__":
    main()