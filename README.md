# Behavior-Based Cloud Threat Detection in AWS using Machine Learning

A cloud security and machine learning project that analyzes AWS CloudTrail logs to detect anomalous behavior, generate refined human-focused alerts, and visualize suspicious activities through an interactive Streamlit dashboard.

The project also includes a DevSecOps layer with Docker, GitHub Actions CI/CD, Trivy security scanning, and Docker Hub image publishing.

---

## Overview

Cloud environments generate a massive number of audit events every day.  
Although these logs contain valuable security signals, manual review is difficult, time-consuming, and not scalable.

This project addresses that challenge by building a behavior-based anomaly detection pipeline for AWS CloudTrail logs. It transforms raw semi-structured log data into investigation-ready alerts and presents the results through a dashboard designed for cloud security analysis.

---

## Key Features

- AWS CloudTrail log preprocessing and cleaning
- Security and behavior-based feature engineering
- Unsupervised anomaly detection using Isolation Forest
- Human-focused alert refinement to reduce automation noise
- Streamlit dashboard for investigation and visualization
- Dockerized dashboard deployment
- GitHub Actions CI/CD pipeline
- Trivy security scanning
- Docker Hub image publishing

---

## Dataset

This project uses the **flaws.cloud CloudTrail dataset**, a public AWS CloudTrail dataset collected from a realistic cloud environment.

### Main fields used
- `eventTime`
- `eventName`
- `eventSource`
- `sourceIPAddress`
- `awsRegion`
- `userIdentity`
- `mfaAuthenticated`
- `errorCode`

> Large raw and intermediate datasets are excluded from Git tracking because of GitHub size limits.

---

## Methodology

### 1. Preprocessing
Raw CloudTrail JSON logs are:
- flattened into tabular format
- cleaned and normalized
- converted into CSV files for analysis

### 2. Feature Engineering
Two categories of features are used.

**Security features**
- root activity
- MFA status
- AccessDenied events
- source IP and region clues

**Behavioral features**
- rare event for a user
- rare IP for a user
- rare region for a user
- unusual activity hour
- user activity frequency patterns

### 3. Anomaly Detection
The project uses **Isolation Forest**, an unsupervised anomaly detection model that does not require labeled attack data.

### 4. Alert Refinement
A refinement layer is applied to:
- reduce AWS internal automation noise
- separate human activity from service-generated activity
- produce more meaningful investigation alerts

### 5. Visualization
A Streamlit dashboard is used to explore and investigate the final suspicious events.

---

## Pipeline

```text
Raw CloudTrail Logs
        ↓
Flattening and Cleaning
        ↓
Feature Engineering
        ↓
Baseline Anomaly Detection
        ↓
Behavior-Based Anomaly Detection
        ↓
Refined Human-Focused Alert Filtering
        ↓
Final Investigation Alerts
        ↓
Streamlit Dashboard
```

---

## DevSecOps Workflow

```text
Source Code
   ↓
GitHub Repository
   ↓
GitHub Actions CI/CD
   ↓
Python Checks
   ↓
Docker Image Build
   ↓
Trivy Security Scan
   ↓
Docker Hub Publish
   ↓
Run Dashboard from Docker Image
```

---

## Current Results

Final outputs from the refined pipeline:

- **All anomalies:** 24,509
- **Human-focused alerts:** 3,513
- **Top unique alerts:** 2,414
- **High-priority alerts:** 2,366

These results represent the final investigation-ready output after preprocessing, anomaly detection, refinement, and filtering.

---

## Dashboard

The dashboard provides:

- summary metrics
- user, event, region, and alert-level filters
- top suspicious users
- top suspicious event types
- top suspicious source IPs
- top suspicious AWS regions
- final ranked investigation alerts

It is designed to make anomaly detection results easier to understand and more useful for cloud security investigation.

---

## Project Structure

```text
cloud-threat-detection/
│
├── app/
│   └── streamlit_app.py
│
├── data/
│   ├── raw/
│   ├── processed/
│   ├── scored/
│   └── final_outputs/
│
├── docs/
│   └── architecture.md
│
├── infra/
│   └── docker/
│       └── Dockerfile
│
├── pipelines/
│   ├── run_dashboard.ps1
│   ├── run_dashboard_docker.ps1
│   └── run_finalize_alerts.ps1
│
├── scripts/
│   ├── analysis/
│   ├── modeling/
│   └── preprocessing/
│
├── security/
│   └── security-notes.md
│
├── tests/
│   └── test_dashboard_smoke.py
│
├── .dockerignore
├── .gitignore
├── requirements.txt
└── README.md
```

---

## Main Components

### Preprocessing
- `flatten_and_clean_all_cloudtrail.py`
- `prepare_features.py`
- `build_behavior_features.py`
- `refine_behavior_features.py`
- `finalize_alerts.py`

### Modeling
- `train_isolation_forest.py`
- `train_behavior_isolation_forest.py`
- `train_refined_behavior_model.py`

### Analysis
- `analyze_csv.py`
- `analyze_anomalies.py`
- `analyze_behavior_anomalies.py`
- `analyze_refined_anomalies.py`
- `compare_models.py`

### Dashboard
- `app/streamlit_app.py`

---

## Local Setup

### Install dependencies
```bash
python -m pip install -r requirements.txt
```

### Generate final alerts
```bash
python .\scripts\preprocessing\finalize_alerts.py
```

### Run the dashboard
```bash
python -m streamlit run .\app\streamlit_app.py
```

---

## Docker

### Build the image
```bash
docker build -f .\infra\docker\Dockerfile -t cloud-threat-detection-dashboard .
```

### Run the container
```bash
docker run --rm -p 8501:8501 cloud-threat-detection-dashboard
```

### Open the dashboard
```text
http://localhost:8501
```

---

## Docker Hub

### Pull the published image
```bash
docker pull abdelazez1/cloud-threat-detection:latest
```

### Run directly from Docker Hub
```bash
docker run --rm -p 8501:8501 abdelazez1/cloud-threat-detection:latest
```

---

## CI/CD

The GitHub Actions pipeline performs:

- dependency installation
- Python smoke checks
- final dashboard data validation
- Docker image build
- Trivy filesystem scan
- Trivy image scan
- Docker Hub image publishing

This allows the project to be automatically built, scanned, and delivered after code changes.

---

## Security Scanning

Security checks are integrated using **Trivy**.

Current scans include:
- filesystem scan
- container image scan

This helps identify:
- high and critical vulnerabilities
- insecure dependencies
- container-related risks

---

## Tech Stack

- Python
- Pandas
- Scikit-learn
- Streamlit
- AWS CloudTrail
- Isolation Forest
- Docker
- GitHub Actions
- Trivy
- Docker Hub

---

## References

- AWS CloudTrail Documentation
- flaws.cloud public CloudTrail dataset
- Scikit-learn Isolation Forest documentation
- AWS GuardDuty documentation
- Recent anomaly detection and log analysis research

---

## Future Improvements

- further reduce false positives
- improve separation between human and automation activity
- add real-time alerting
- deploy the dashboard to a cloud environment
- compare additional anomaly detection models
- expand DevSecOps checks and policy validation

---

## Conclusion

This project demonstrates how behavior-based anomaly detection can be used to identify suspicious cloud activities from AWS CloudTrail logs.

By combining preprocessing, feature engineering, anomaly detection, alert refinement, dashboard visualization, Docker containerization, CI/CD automation, and security scanning, the project provides a practical and extensible cloud threat detection workflow.
