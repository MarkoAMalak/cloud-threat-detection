import os
import pandas as pd
import streamlit as st

BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DATA_DIR = os.path.join(BASE_DIR, "data", "final_outputs")

ALL_ANOMALIES_CSV = os.path.join(DATA_DIR, "final_all_anomalies.csv")
HUMAN_ALERTS_CSV = os.path.join(DATA_DIR, "final_human_alerts.csv")
TOP_ALERTS_CSV = os.path.join(DATA_DIR, "final_top_alerts.csv")

st.set_page_config(page_title="Cloud Threat Detection Dashboard", layout="wide")


@st.cache_data
def load_data():
    all_df = pd.read_csv(ALL_ANOMALIES_CSV)
    human_df = pd.read_csv(HUMAN_ALERTS_CSV)
    top_df = pd.read_csv(TOP_ALERTS_CSV)
    return all_df, human_df, top_df


def safe_series(df, col):
    if col in df.columns:
        return df[col]
    return pd.Series([], dtype="object")


def main():
    st.title("Behavior-Based Cloud Threat Detection in AWS")
    st.caption("Final investigation dashboard for anomalous CloudTrail events")

    all_df, human_df, top_df = load_data()

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("All anomalies", len(all_df))
    c2.metric("Human-focused alerts", len(human_df))
    c3.metric("Top unique alerts", len(top_df))
    c4.metric("High-priority alerts", int((safe_series(top_df, "final_alert_label") == "high").sum()))

    st.divider()

    st.subheader("Filters")

    usernames = ["All"] + sorted(safe_series(top_df, "username").dropna().astype(str).unique().tolist())
    events = ["All"] + sorted(safe_series(top_df, "eventName").dropna().astype(str).unique().tolist())
    regions = ["All"] + sorted(safe_series(top_df, "awsRegion").dropna().astype(str).unique().tolist())
    labels = ["All"] + sorted(safe_series(top_df, "final_alert_label").dropna().astype(str).unique().tolist())

    f1, f2, f3, f4 = st.columns(4)
    selected_user = f1.selectbox("Username", usernames)
    selected_event = f2.selectbox("Event Name", events)
    selected_region = f3.selectbox("AWS Region", regions)
    selected_label = f4.selectbox("Final Alert Label", labels)

    filtered = top_df.copy()

    if selected_user != "All":
        filtered = filtered[filtered["username"] == selected_user]
    if selected_event != "All":
        filtered = filtered[filtered["eventName"] == selected_event]
    if selected_region != "All":
        filtered = filtered[filtered["awsRegion"] == selected_region]
    if selected_label != "All":
        filtered = filtered[filtered["final_alert_label"] == selected_label]

    st.divider()

    left, right = st.columns(2)

    with left:
        st.subheader("Top suspicious users")
        user_counts = filtered["username"].value_counts().head(10)
        st.bar_chart(user_counts)

    with right:
        st.subheader("Top suspicious event names")
        event_counts = filtered["eventName"].value_counts().head(10)
        st.bar_chart(event_counts)

    left2, right2 = st.columns(2)

    with left2:
        st.subheader("Top suspicious source IPs")
        ip_counts = filtered["sourceIPAddress"].value_counts().head(10)
        st.bar_chart(ip_counts)

    with right2:
        st.subheader("Top suspicious regions")
        region_counts = filtered["awsRegion"].value_counts().head(10)
        st.bar_chart(region_counts)

    st.divider()

    st.subheader("Final investigation alerts")
    show_cols = [
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

    existing_cols = [c for c in show_cols if c in filtered.columns]
    display_df = filtered[existing_cols].sort_values(by="final_alert_score", ascending=False)

    st.dataframe(display_df, use_container_width=True, height=500)

    st.divider()

    st.subheader("Human-focused anomaly sample")
    human_show = [
        "eventTime",
        "eventName",
        "eventSource",
        "username",
        "sourceIPAddress",
        "awsRegion",
        "review_priority",
        "refined_risk_score",
        "anomaly_score",
    ]
    human_existing = [c for c in human_show if c in human_df.columns]
    st.dataframe(human_df[human_existing].head(100), use_container_width=True, height=350)


if __name__ == "__main__":
    main()