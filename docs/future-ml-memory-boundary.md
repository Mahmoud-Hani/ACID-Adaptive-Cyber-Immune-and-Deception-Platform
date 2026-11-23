# Future ML Memory Boundary

## 1. Purpose

This document defines the planned boundaries for the future ML memory component in ACID.

The goal is to prepare the feature engineering and integration design without implementing model training in the current phase.

## 2. Planned Event Features

The future ML model may consume the following fields from normalized ACID Events:

| Feature | Description |
|---|---|
| `src_ip` | Source IP address |
| `dst_ip` | Destination IP address |
| `src_port` | Source port |
| `dst_port` | Destination port |
| `protocol` | Network protocol, such as TCP or UDP |
| `event_type` | Type of observed event |
| `source` | Original event source |

These fields will require preprocessing and validation before model inference.

## 3. CTI Context Boundary

Cyber Threat Intelligence (CTI) enrichment is additional context, not conclusive evidence of malicious activity.

- A CTI No-Hit result does not mean that an IP address is benign.
- A matching threat-intelligence indicator does not independently prove malicious activity.
- A port scan alone does not prove that a vulnerability (CVE) exists.
- CTI information should be correlated with observed behavior and other security evidence.

## 4. ML Risk Score Boundary

The future ML component will provide a risk score as an additional signal.

- The ML score must not be treated as a final security verdict.
- The score should support analyst investigation and prioritization.
- Final decisions must consider event evidence, CTI context, and detection results.
- The model must not automatically confirm a vulnerability based only on a port scan.

## 5. Current Development Scope

During the current development phase:

- Prepare the feature definitions.
- Define the future API integration boundary.
- Implement a mock prediction response.
- Prepare an Isolation Forest mock script.
- Do not train a model.
- Do not call `fit()` or claim that the mock score is a trained prediction.

## 6. Future Work

The following activities are reserved for a future phase:

- Dataset collection and preparation.
- Feature engineering implementation.
- Model training and evaluation.
- Threshold selection.
- Model monitoring and versioning.
- Integration with the ACID detection pipeline.
