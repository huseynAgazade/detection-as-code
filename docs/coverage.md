# Detection coverage

Generated from the rule catalogue by `python -m pipelines.tools.coverage`. Do not edit by hand.

**7 rules** covering **9 ATT&CK techniques** across **6 tactics**.

## ATT&CK tactic coverage

| Tactic | ID | Rules | Covered by |
|--------|----|-------|------------|
| Reconnaissance | TA0043 | 0 | _no coverage_ |
| Resource Development | TA0042 | 0 | _no coverage_ |
| Initial Access | TA0001 | 1 | `CLD-IAM-001` |
| Execution | TA0002 | 1 | `EDR-PRC-001` |
| Persistence | TA0003 | 0 | _no coverage_ |
| Privilege Escalation | TA0004 | 0 | _no coverage_ |
| Defense Evasion | TA0005 | 3 | `EDR-PRC-001`, `OPS-HLT-001`, `OS-WIN-001` |
| Credential Access | TA0006 | 2 | `ID-AD-001`, `WEB-WAF-001` |
| Discovery | TA0007 | 0 | _no coverage_ |
| Lateral Movement | TA0008 | 0 | _no coverage_ |
| Collection | TA0009 | 0 | _no coverage_ |
| Command and Control | TA0011 | 1 | `NET-DNS-001` |
| Exfiltration | TA0010 | 1 | `NET-DNS-001` |
| Impact | TA0040 | 0 | _no coverage_ |

## Platform coverage

| Platform | Rules |
|----------|-------|
| splunk | 7 |
| sentinel | 3 |
| elastic | 2 |

## Lifecycle status

| Status | Rules |
|--------|-------|
| stable | 6 |
| experimental | 1 |

## Severity distribution

| Severity | Rules |
|----------|-------|
| high | 4 |
| medium | 3 |

## Log source dependencies

| Data source | Rules |
|-------------|-------|
| Windows Security Event Log | 2 |
| Cloud Provider Control-Plane Audit Logs | 1 |
| Cloud Console Sign-In Events | 1 |
| Endpoint Process Creation Events | 1 |
| Windows Security Event Log (4688) or Sysmon Event ID 1 | 1 |
| Domain Controller Kerberos Service Ticket Operations (4769) | 1 |
| DNS Query Logs | 1 |
| DNS Resolver or Firewall DNS Inspection Logs | 1 |
| SIEM Ingestion Metadata | 1 |
| Windows Event Log Service Events (1102) | 1 |
| Web Application Firewall Logs | 1 |
| Reverse Proxy or Load Balancer Access Logs | 1 |

