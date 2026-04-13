import pandas as pd

INPUT_CSV = "model_input.csv"
OUTPUT_CSV = "behavior_model_input.csv"


def main():
    print("Loading model_input.csv ...")
    use_cols = [
        "eventTime",
        "eventName",
        "eventSource",
        "username",
        "awsRegion",
        "sourceIPAddress",
        "hour",
        "day_of_week",
        "month",
        "is_weekend",
        "is_root",
        "is_error",
        "is_access_denied",
        "is_mfa_false",
        "is_iam_event",
        "is_cloudtrail_event",
        "is_console_login",
        "is_s3_event",
        "is_ec2_event",
        "is_from_unknown_ip",
        "is_us_east_1",
        "risk_score",
        "source_ip_is_real",
        "source_ip_is_service",
        "user_agent_is_console",
        "user_agent_is_cli",
        "user_agent_is_sdk",
        "risk_level",
    ]

    df = pd.read_csv(INPUT_CSV, usecols=use_cols)

    print(f"Rows loaded: {len(df)}")

    # تنظيف بسيط
    for col in ["eventName", "eventSource", "username", "awsRegion", "sourceIPAddress"]:
        df[col] = df[col].fillna("unknown").astype(str).str.strip()

    # تحويل الوقت
    df["eventTime"] = pd.to_datetime(df["eventTime"], errors="coerce", utc=True)
    df = df.sort_values("eventTime").reset_index(drop=True)

    print("Building behavioral aggregates...")

    # إجمالي عدد الأحداث لكل مستخدم
    df["user_total_events"] = df.groupby("username")["username"].transform("count")

    # عدد الأحداث لنفس المستخدم في نفس الساعة
    df["user_hour_count"] = (
        df.groupby(["username", "hour"])["username"].transform("count")
    )

    # عدد الأحداث لنفس المستخدم في نفس اليوم من الأسبوع
    df["user_dayofweek_count"] = (
        df.groupby(["username", "day_of_week"])["username"].transform("count")
    )

    # عدد مرات هذا الحدث لنفس المستخدم
    df["user_event_count"] = (
        df.groupby(["username", "eventName"])["username"].transform("count")
    )

    # عدد مرات هذا الـ service لنفس المستخدم
    df["user_source_count"] = (
        df.groupby(["username", "eventSource"])["username"].transform("count")
    )

    # عدد مرات هذا الـ IP لنفس المستخدم
    df["user_ip_count"] = (
        df.groupby(["username", "sourceIPAddress"])["username"].transform("count")
    )

    # عدد مرات هذا الـ region لنفس المستخدم
    df["user_region_count"] = (
        df.groupby(["username", "awsRegion"])["username"].transform("count")
    )

    # عدد مرات الحدث عالميًا
    df["global_event_count"] = (
        df.groupby("eventName")["eventName"].transform("count")
    )

    # عدد مرات الـ source عالميًا
    df["global_source_count"] = (
        df.groupby("eventSource")["eventSource"].transform("count")
    )

    # عدد مرات الـ IP عالميًا
    df["global_ip_count"] = (
        df.groupby("sourceIPAddress")["sourceIPAddress"].transform("count")
    )

    # عدد الـ IPs المختلفة لكل مستخدم
    user_unique_ips = (
        df.groupby("username")["sourceIPAddress"].nunique().rename("user_unique_ip_count")
    )
    df = df.merge(user_unique_ips, on="username", how="left")

    # عدد الـ regions المختلفة لكل مستخدم
    user_unique_regions = (
        df.groupby("username")["awsRegion"].nunique().rename("user_unique_region_count")
    )
    df = df.merge(user_unique_regions, on="username", how="left")

    # عدد الـ eventNames المختلفة لكل مستخدم
    user_unique_events = (
        df.groupby("username")["eventName"].nunique().rename("user_unique_event_count")
    )
    df = df.merge(user_unique_events, on="username", how="left")

    print("Building rarity ratios...")

    # ratios
    df["user_event_ratio"] = df["user_event_count"] / df["user_total_events"]
    df["user_source_ratio"] = df["user_source_count"] / df["user_total_events"]
    df["user_ip_ratio"] = df["user_ip_count"] / df["user_total_events"]
    df["user_region_ratio"] = df["user_region_count"] / df["user_total_events"]
    df["user_hour_ratio"] = df["user_hour_count"] / df["user_total_events"]

    # flags للندرة
    df["is_rare_event_for_user"] = (df["user_event_count"] <= 3).astype(int)
    df["is_rare_source_for_user"] = (df["user_source_count"] <= 3).astype(int)
    df["is_rare_ip_for_user"] = (df["user_ip_count"] <= 2).astype(int)
    df["is_rare_region_for_user"] = (df["user_region_count"] <= 2).astype(int)
    df["is_rare_hour_for_user"] = (df["user_hour_count"] <= 2).astype(int)

    # flags عالمية
    df["is_globally_rare_event"] = (df["global_event_count"] <= 10).astype(int)
    df["is_globally_rare_ip"] = (df["global_ip_count"] <= 10).astype(int)

    # score سلوكي بسيط
    df["behavior_risk_score"] = (
        df["is_rare_event_for_user"]
        + df["is_rare_source_for_user"]
        + df["is_rare_ip_for_user"] * 2
        + df["is_rare_region_for_user"]
        + df["is_rare_hour_for_user"]
        + df["is_globally_rare_event"]
        + df["is_globally_rare_ip"]
    )

    print("Saving behavior_model_input.csv ...")
    df.to_csv(OUTPUT_CSV, index=False)

    print("\nDone.")
    print(f"Output file: {OUTPUT_CSV}")
    print(f"Rows saved : {len(df)}")
    print("\nNew behavioral columns added:")
    print("- user_total_events")
    print("- user_hour_count")
    print("- user_dayofweek_count")
    print("- user_event_count")
    print("- user_source_count")
    print("- user_ip_count")
    print("- user_region_count")
    print("- user_unique_ip_count")
    print("- user_unique_region_count")
    print("- user_unique_event_count")
    print("- user_event_ratio")
    print("- user_source_ratio")
    print("- user_ip_ratio")
    print("- user_region_ratio")
    print("- user_hour_ratio")
    print("- is_rare_event_for_user")
    print("- is_rare_source_for_user")
    print("- is_rare_ip_for_user")
    print("- is_rare_region_for_user")
    print("- is_rare_hour_for_user")
    print("- is_globally_rare_event")
    print("- is_globally_rare_ip")
    print("- behavior_risk_score")


if __name__ == "__main__":
    main()