import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder

INPUT_CSV = "behavior_model_input_refined.csv"
OUTPUT_CSV = "cloudtrail_behavior_refined_scored.csv"

CATEGORICAL_COLUMNS = [
    "eventName",
    "eventSource",
    "username",
    "awsRegion",
]

NUMERIC_COLUMNS = [
    # original
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

    # behavior
    "user_total_events",
    "user_hour_count",
    "user_dayofweek_count",
    "user_event_count",
    "user_source_count",
    "user_ip_count",
    "user_region_count",
    "global_event_count",
    "global_source_count",
    "global_ip_count",
    "user_unique_ip_count",
    "user_unique_region_count",
    "user_unique_event_count",
    "user_event_ratio",
    "user_source_ratio",
    "user_ip_ratio",
    "user_region_ratio",
    "user_hour_ratio",
    "is_rare_event_for_user",
    "is_rare_source_for_user",
    "is_rare_ip_for_user",
    "is_rare_region_for_user",
    "is_rare_hour_for_user",
    "is_globally_rare_event",
    "is_globally_rare_ip",
    "behavior_risk_score",

    # refined
    "is_internal_service_ip",
    "is_service_user",
    "is_human_user",
    "is_automation_activity",
    "is_human_activity",
    "is_root_human_activity",
    "is_suspicious_access_denied_human",
    "refined_risk_score",
]

REVIEW_COLUMNS = [
    "eventTime",
    "eventName",
    "eventSource",
    "username",
    "awsRegion",
    "sourceIPAddress",
    "risk_level",
    "review_priority",
    "risk_score",
    "behavior_risk_score",
    "refined_risk_score",
    "is_automation_activity",
    "is_human_activity",
]


def main():
    print("Loading refined behavior dataset ...")
    df = pd.read_csv(INPUT_CSV)

    print(f"Rows loaded: {len(df)}")
    print(f"Columns loaded: {len(df.columns)}")

    for col in CATEGORICAL_COLUMNS:
        df[col] = df[col].fillna("unknown").astype(str)

    for col in NUMERIC_COLUMNS:
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

    X = df[CATEGORICAL_COLUMNS + NUMERIC_COLUMNS].copy()

    preprocessor = ColumnTransformer(
        transformers=[
            ("cat", OneHotEncoder(handle_unknown="ignore"), CATEGORICAL_COLUMNS),
            ("num", "passthrough", NUMERIC_COLUMNS),
        ]
    )

    model = IsolationForest(
        n_estimators=100,
        contamination=0.02,
        random_state=42,
        n_jobs=-1,
    )

    pipeline = Pipeline(
        steps=[
            ("preprocessor", preprocessor),
            ("model", model),
        ]
    )

    print("Training refined behavior model ...")
    pipeline.fit(X)

    print("Scoring anomalies ...")
    predictions = pipeline.predict(X)
    anomaly_scores = pipeline.decision_function(X)

    df["prediction"] = predictions
    df["anomaly_score"] = anomaly_scores
    df["is_anomaly"] = (df["prediction"] == -1).astype(int)

    df_sorted = df.sort_values(by="anomaly_score", ascending=True).copy()

    print("Saving output ...")
    df_sorted.to_csv(OUTPUT_CSV, index=False)

    total_anomalies = int(df["is_anomaly"].sum())
    anomaly_ratio = (total_anomalies / len(df)) * 100

    print("\nDone.")
    print(f"Output file      : {OUTPUT_CSV}")
    print(f"Total rows       : {len(df)}")
    print(f"Anomalies found  : {total_anomalies}")
    print(f"Anomaly percent  : {anomaly_ratio:.2f}%")

    print("\nTop 10 most anomalous events:")
    cols_to_show = REVIEW_COLUMNS + ["anomaly_score", "prediction", "is_anomaly"]
    print(df_sorted[cols_to_show].head(10).to_string(index=False))


if __name__ == "__main__":
    main()