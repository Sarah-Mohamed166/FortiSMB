<p align="center">
  <img src="assets/logo.png" width="180"/>
</p>

<h1 align="center">FortiSMB</h1>
<p align="center">
  Explainable AI Framework for Insider Threat Detection in SMB Environments
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.10-blue" />
  <img src="https://img.shields.io/badge/Status-Research%20Project-orange" />
  <img src="https://img.shields.io/badge/Domain-Cybersecurity-black" />
  <img src="https://img.shields.io/badge/AI-Explainable%20AI-gold" />
</p>

---

## Overview

FortiSMB is an AI-driven cybersecurity framework designed to detect insider threats in Small and Medium Business environments. It combines anomaly detection, role-based access control, and explainable AI to identify suspicious behavior and generate interpretable alerts.

## Problem Statement

Traditional security systems often fail to detect insider threats because insider behavior can appear legitimate, labeled attack data is limited, and many AI systems do not provide transparent reasoning behind their decisions.

## Proposed Solution

FortiSMB introduces a hybrid framework that:

* detects anomalous behavior using machine learning
* validates suspicious actions through RBAC-based policy checks
* explains risk predictions using XAI techniques
* supports alert generation and security analysis

## Key Features

* Insider threat detection using anomaly detection
* Role-Based Access Control validation
* Explainable AI support
* Risk scoring and visualization
* Security-oriented analysis workflow

## System Architecture

<p align="center">
  <img src="assets/architecture.png" width="850"/>
</p>

## Results and Visualizations

### Anomaly Score Distribution

<p align="center">
  <img src="assets/anomaly_distribution.png" width="750"/>
</p>

### RBAC Violations Analysis

<p align="center">
  <img src="assets/rbac_violations.png" width="750"/>
</p>

### Kernel Density Estimation

<p align="center">
  <img src="assets/kde_analysis.png" width="750"/>
</p>

### Path Length Formulation

<p align="center">
  <img src="assets/path_length.png" width="750"/>
</p>

### Risk Distribution

<p align="center">
  <img src="assets/risk_distribution.png" width="750"/>
</p>

## Project Structure

```bash
FortiSMB/
├── assets/
│   ├── architecture.png
│   ├── anomaly_distribution.png
│   ├── rbac_violations.png
│   ├── kde_analysis.png
│   ├── path_length.png
│   ├── risk_distribution.png
│   └── logo.png
├── data/
├── src/
├── .gitignore
├── LICENSE
├── README.md
└── requirements.txt
```

## Installation

```bash
git clone https://github.com/Sarah-Mohamed166/FortiSMB.git
cd FortiSMB
pip install -r requirements.txt
```

## Usage

```bash
python src/main.py
```

## Dataset

This project uses the CERT Insider Threat Dataset.

## Author

Sara Walid Mohamed
---

## 📜 License

This project is licensed under the MIT License.

You are free to use, modify, and distribute this software, provided that proper credit is given to the original author.

For more details, see the [LICENSE](./LICENSE) file.

