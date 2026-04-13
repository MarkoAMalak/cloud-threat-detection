# Project Architecture

## High-Level Flow

```text
Raw CloudTrail Logs
        ↓
Preprocessing
        ↓
Feature Engineering
        ↓
Baseline Isolation Forest
        ↓
Behavior-Based Isolation Forest
        ↓
Refined Human-Focused Alerts
        ↓
Final Investigation Outputs
        ↓
Streamlit Dashboard
        ↓
Docker + GitHub Actions + Trivy + Docker Hub
```

## Components

### 1. Data Layer
- Raw AWS CloudTrail logs from the flaws.cloud dataset
- Stored locally under `data/raw/`

### 2. Processing Layer
- Flattening and cleaning raw JSON logs
- Converting logs into processed CSV files
- Preparing data for feature engineering

### 3. Feature Layer
- Security features:
  - root activity
  - MFA status
  - AccessDenied events
  - region and source IP clues
- Behavioral features:
  - rare event for a user
  - rare region for a user
  - rare IP for a user
  - unusual activity hour

### 4. Modeling Layer
- Baseline anomaly detection using Isolation Forest
- Behavior-based anomaly detection using refined features
- Final refinement step to reduce AWS automation noise

### 5. Alerting Layer
- Final anomaly outputs
- Human-focused filtered alerts
- Top unique investigation-ready alerts

### 6. Visualization Layer
- Streamlit dashboard for:
  - summary metrics
  - investigation filters
  - suspicious users / IPs / regions
  - final alert table

### 7. DevSecOps Layer
- Docker containerization
- GitHub Actions CI/CD
- Trivy security scanning
- Docker Hub image publishing
