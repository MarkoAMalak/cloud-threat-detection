import os
import pandas as pd

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
INPUT_CSV = os.path.join(BASE_DIR, "data", "scored", "cloudtrail_behavior_refined_scored.csv")

OUTPUT_DIR = os.path.join(BASE_DIR, "data", "final_outputs")
OUTPUT_ALL = os.path.join(OUTPUT_DIR, "final_all_anomalies.csv")
OUTPUT_HUMAN = os.path.join(OUTPUT_DIR, "final_human_alerts.csv")
OUTPUT_TOP = os.path.join(OUTPUT_DIR, "final_top_alerts.csv")

def normalize_text(series):
    return series.fillna("unknown").astype(str).str.strip()


def strict_is_automation_user(username: str) -> int:
    u = str(username).strip().lower()

    patterns = [
        "aws:",
        "awsservicerole",
        "config-role",
        "service-role",
        "lambda_",
        "lambdabasicexecution",
        "lambda_basic_execution",
        "cloudtrail",
        "organizations",
        "configmultiaccountsetup",
    ]

    exact = {
        "aws:ec2-instance",
        "awsserviceroleforsupport",
        "awsserviceroleforcloudtrail",
        "awsservicerolefororganizations",
        "awsserviceroleforconfigmultiaccountsetup",
        "lambda_basic_execution",
    }

    if u in exact:
        return 1

    for p in patterns:
        if u.startswith(p) or p in u:
            return 1

    return 0


def strict_is_automation_ip(value: str) -> int:
    v = str(value).strip().lower()
    if v == "aws internal":
        return 1
    if v.endswith(".amazonaws.com"):
        return 1
    return 0


def strict_is_human_user(username: str) -> int:
    u = str(username).strip().lower()

    if u == "unknown":
        return 0

    if strict_is_automation_user(u) == 1:
        return 0

    if u.startswith("arn:aws:iam::") and ":root" in u:
        return 1

    if u.startswith("arn:aws:iam::") and ":user/" in u:
        return 1

    if u.startswith("arn:aws:sts::") and "assumed-role" in u:
        if "service-role" not in u and "awsservicerole" not in u:
            return 1

    if "/" not in u and ":" not in u and ".amazonaws.com" not in u and "role" not in u:
        return 1

    return 0


def build_final_label(row):
    if row["final_is_human_alert"] == 1 and row["review_priority"] == "high":
        return "high"
    if row["final_is_human_alert"] == 1 and row["review_priority"] == "medium":
        return "medium"
    return "low"


def main():
    print("Loading refined scored anomalies ...")
    df = pd.read_csv(INPUT_CSV)

    print(f"Rows loaded: {len(df)}")

    text_cols = [
        "username",
        "sourceIPAddress",
        "eventName",
        "eventSource",
        "awsRegion",
        "review_priority",
        "risk_level",
    ]
    for col in text_cols:
        df[col] = normalize_text(df[col])

    print("Building strict final alert filters ...")

    df["strict_automation_user"] = df["username"].apply(strict_is_automation_user).astype(int)
    df["strict_automation_ip"] = df["sourceIPAddress"].apply(strict_is_automation_ip).astype(int)
    df["strict_human_user"] = df["username"].apply(strict_is_human_user).astype(int)

    df["strict_automation_activity"] = (
        (df["strict_automation_user"] == 1)
        | (df["strict_automation_ip"] == 1)
        | (df["is_automation_activity"] == 1)
    ).astype(int)

    df["strict_human_activity"] = (
        (df["strict_human_user"] == 1)
        & (df["strict_automation_activity"] == 0)
    ).astype(int)

    df["final_is_human_alert"] = (
        (df["is_anomaly"] == 1)
        & (df["strict_human_activity"] == 1)
        & (df["review_priority"].isin(["high", "medium"]))
    ).astype(int)

    df["final_alert_score"] = (
        pd.to_numeric(df["refined_risk_score"], errors="coerce").fillna(0)
        - pd.to_numeric(df["anomaly_score"], errors="coerce").fillna(0) * 100
    )

    df["final_alert_label"] = df.apply(build_final_label, axis=1)

    all_anomalies = df[df["is_anomaly"] == 1].copy()
    human_alerts = df[df["final_is_human_alert"] == 1].copy()

    dedup_cols = ["eventTime", "eventName", "eventSource", "username", "sourceIPAddress", "awsRegion"]
    top_alerts = (
        human_alerts
        .sort_values(by=["final_alert_score", "anomaly_score"], ascending=[False, True])
        .drop_duplicates(subset=dedup_cols)
        .copy()
    )

    os.makedirs(OUTPUT_DIR, exist_ok=True)

    print("Saving files ...")
    all_anomalies.to_csv(OUTPUT_ALL, index=False)
    human_alerts.to_csv(OUTPUT_HUMAN, index=False)
    top_alerts.to_csv(OUTPUT_TOP, index=False)

    print("\nDone.")
    print(f"Output folder          : {OUTPUT_DIR}")
    print(f"All anomalies file     : {OUTPUT_ALL}")
    print(f"Human alerts file      : {OUTPUT_HUMAN}")
    print(f"Top alerts file        : {OUTPUT_TOP}")
    print(f"All anomaly rows       : {len(all_anomalies)}")
    print(f"Final human alert rows : {len(human_alerts)}")
    print(f"Top unique alert rows  : {len(top_alerts)}")

    print("\nTop 15 final alerts:")
    cols = [
        "eventTime",
        "eventName",
        "eventSource",
        "username",
        "sourceIPAddress",
        "awsRegion",
        "review_priority",
        "final_alert_label",
        "refined_risk_score",
        "anomaly_score",
        "final_alert_score",
    ]
    print(top_alerts[cols].head(15).to_string(index=False))


if __name__ == "__main__":
    main()