# Threat Model

## Purpose

This document defines the security scope of the project, the main threats the system is intended to help detect, and the current limitations.

---

## System Goal

The system is designed to detect suspicious cloud activities from AWS CloudTrail logs using machine learning and behavior-based anomaly detection.

It is intended to support:
- cloud security monitoring
- suspicious activity triage
- investigation support

It is **not** intended to replace enterprise SIEM, EDR, or fully managed threat detection platforms.

---

## Assets

The main assets relevant to this project are:

- AWS CloudTrail audit logs
- processed and scored anomaly outputs
- final investigation alerts
- the Streamlit dashboard
- Docker image and CI/CD workflow
- source code and pipeline logic

---

## Assumptions

This project assumes that:

- CloudTrail logs are available and correctly collected
- the dataset is representative enough for anomaly detection experiments
- final dashboard users are security analysts, researchers, or students
- the dashboard is used for investigation support, not automatic response
- the environment is mainly batch-analysis oriented, not real-time detection

---

## Intended User

The main intended user is:

- a security analyst
- a cloud security engineer
- a researcher or student investigating suspicious cloud behavior

The dashboard is primarily designed for **investigation and triage**, not for executive reporting.

---

## Threats the Project Helps Detect

The system is mainly intended to help highlight:

### 1. Privileged Misuse
Examples:
- unusual root activity
- suspicious IAM activity
- sensitive API usage patterns

### 2. Account Compromise Indicators
Examples:
- unusual user behavior
- activity from rare source IPs
- region changes
- unusual access timing

### 3. Suspicious API Behavior
Examples:
- repeated bucket listing
- unexpected configuration queries
- unusual service access patterns

### 4. Reconnaissance / Enumeration Behavior
Examples:
- repeated CloudTrail or IAM queries
- suspicious discovery actions
- repeated AccessDenied activity

---

## Threats Not Fully Covered

This project does **not** fully address:

- real-time detection and response
- endpoint compromise
- malware execution inside instances
- network packet analysis
- data exfiltration confirmation
- identity federation abuse beyond visible CloudTrail behavior
- full enterprise incident response workflows

---

## Main Security Limitations

### 1. False Positives
Rare activity is not always malicious.

### 2. Automation Noise
AWS internal services and automated roles can appear anomalous.

### 3. Dataset Scope
The project relies on a public dataset, which may not represent all real-world cloud environments.

### 4. Batch Orientation
The current pipeline is oriented toward offline analysis rather than live streaming detection.

---

## Security Controls Added in the Project

The project includes several controls to improve reliability and security posture:

- refined human-focused alert filtering
- Docker-based packaging
- GitHub Actions CI/CD
- Trivy security scanning
- repository structure separation for code, data, security, and pipelines

---

## Future Security Improvements

Potential future improvements include:

- live detection pipeline
- stronger user/entity baselining
- more robust service-account filtering
- policy-as-code checks
- more security tests in CI/CD
- deployment to a monitored cloud environment
