# Azure Security Monitoring with Microsoft Sentinel

![Azure](https://img.shields.io/badge/Azure-Security%20Monitoring-0078D4?style=for-the-badge&logo=microsoftazure)
![Status](https://img.shields.io/badge/Status-Complete-brightgreen?style=for-the-badge)

## Overview
This project implements a **Security Monitoring and Threat Detection** solution using Microsoft Sentinel (SIEM) on Azure. It demonstrates real-world SOC workflows including log ingestion, KQL detection rules, and security dashboards.

## Architecture
law-sentinel-project (Log Analytics Workspace)
├── Microsoft Sentinel (SIEM)
│   ├── Data Connectors
│   │   ├── Azure Activity (subscription-level events)
│   │   └── Microsoft Entra ID Protection (identity risks)
│   ├── Analytics Rules
│   │   ├── Failed Sign-In Attempts Detection (Medium)
│   │   └── Suspicious Resource Deletion Detected (High)
│   └── Workbooks
│       └── Security Monitoring Dashboard

## What I Built
- **Log Analytics Workspace** as the data foundation for Sentinel
- **Microsoft Sentinel** SIEM enabled and connected to Defender portal
- **Data Connectors** ingesting Azure Activity and Entra ID logs
- **KQL Detection Rules** for brute force and resource deletion attacks
- **Security Dashboard** for SOC monitoring and visibility

## Detection Rules

| Rule | Severity | MITRE ATT&CK | Description |
|------|----------|--------------|-------------|
| Failed Sign-In Attempts | Medium | T1110 - Brute Force | Detects 5+ failed logins per user per hour |
| Suspicious Resource Deletion | High | T1485 - Data Destruction | Detects 3+ resource deletions per hour |

## KQL Queries

### Failed Sign-In Detection
```kql
SigninLogs
| where ResultType != 0
| summarize FailedAttempts = count() by UserPrincipalName, IPAddress, bin(TimeGenerated, 1h)
| where FailedAttempts >= 5
```

### Resource Deletion Detection
```kql
AzureActivity
| where OperationNameValue endswith "delete"
| where ActivityStatusValue == "Success"
| summarize DeleteCount = count() by Caller, ResourceGroup, bin(TimeGenerated, 1h)
| where DeleteCount >= 3
```

## Security Controls Implemented

| Control | Implementation |
|---------|---------------|
| Log Ingestion | Azure Activity + Entra ID connectors |
| Threat Detection | 2 custom KQL analytics rules |
| Incident Creation | Automated from analytics rule alerts |
| SOC Dashboard | Azure Activity workbook |
| MITRE ATT&CK Mapping | T1110, T1485 |

## Key Learnings
- Microsoft Sentinel is a cloud-native SIEM built on Log Analytics
- KQL is the core language for threat detection and hunting
- Data connectors are the foundation and no logs means no detection
- Analytics rules automate threat detection and create incidents
- Workbooks provide SOC visibility across the environment
- MITRE ATT&CK mapping connects detections to real attacker behavior

## Related Projects
- Project 1: [Zero Trust Network Security](https://github.com/fritzekane/azure-zerotrust-network-security)
- Project 2: [IAM Hardening with Microsoft Entra ID](https://github.com/fritzekane/azure-iam-entra-id)
- Project 4: [Compliance Automation with Azure Policy](coming soon)

---
*Part of my Azure Cloud Security Portfolio — 7 hands-on projects demonstrating real-world security engineering skills.*
