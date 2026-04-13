import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder


INPUT_CSV = "model_input.csv"
OUTPUT_CSV = "cloudtrail_scored.csv"

# الأعمدة النصية
CATEGORICAL_COLUMNS = [
    "eventName",
    "eventSource",
    "username",
    "awsRegion",
]

# الأعمدة الرقمية / الثنائية
NUMERIC_COLUMNS = [
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
]

# أعمدة نحتفظ بها في الناتج للمراجعة
REVIEW_COLUMNS = [
    "eventTime",
    "eventName",
    "eventSource",
    "username",
    "awsRegion",
    "sourceIPAddress",
    "risk_level",
]


def main():
    print("Loading CSV...")
    df = pd.read_csv(INPUT_CSV)

    print(f"Rows loaded: {len(df)}")
    print(f"Columns loaded: {len(df.columns)}")

    # معالجة القيم الفارغة
    for col in CATEGORICAL_COLUMNS:
        df[col] = df[col].fillna("unknown").astype(str)

    for col in NUMERIC_COLUMNS:
        df[col] = pd.to_numeric(df[col], errors="coerce").fillna(0)

    # تجهيز البيانات للموديل
    X = df[CATEGORICAL_COLUMNS + NUMERIC_COLUMNS].copy()

    preprocessor = ColumnTransformer(
        transformers=[
            (
                "cat",
                OneHotEncoder(handle_unknown="ignore"),
                CATEGORICAL_COLUMNS,
            ),
            (
                "num",
                "passthrough",
                NUMERIC_COLUMNS,
            ),
        ]
    )

    model = IsolationForest(
        n_estimators=100,
        contamination=0.02,   # 2% anomalies كبداية
        random_state=42,
        n_jobs=-1,
    )

    pipeline = Pipeline(
        steps=[
            ("preprocessor", preprocessor),
            ("model", model),
        ]
    )

    print("Training Isolation Forest...")
    pipeline.fit(X)

    print("Scoring anomalies...")
    predictions = pipeline.predict(X)              # -1 anomaly, 1 normal
    anomaly_scores = pipeline.decision_function(X) # smaller = more anomalous

    df["prediction"] = predictions
    df["anomaly_score"] = anomaly_scores

    # نخلي flag أوضح
    df["is_anomaly"] = df["prediction"].apply(lambda x: 1 if x == -1 else 0)

    # ترتيب النتائج: الأكثر شذوذًا أولًا
    df_sorted = df.sort_values(by="anomaly_score", ascending=True).copy()

    print("Saving scored CSV...")
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