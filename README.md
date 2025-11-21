# Wazuh Lab Work & Proof-of-Concept Exercises

This repository consolidates a series of hands-on lab exercises and proof-of-concept implementations using the Wazuh Security Information and Event Management (SIEM) platform. The materials are derived from guided lab work and are intended to provide a theoretical and practical overview of Wazuh's core capabilities.

**Note on Proof-of-Concept (PoC) Scripts:** This repository includes a Python script for simulating a ransomware attack, located in the `scripts/` directory. This script is for educational and archival purposes only. **DO NOT RUN THIS SCRIPT** on any production or critical systems.

## Core Concepts & Theory

### 1. Wazuh Architecture & Setup

Wazuh is an open-source security platform that provides unified SIEM and XDR capabilities. Its architecture consists of three main components:

*   **Wazuh Server:** The central component that collects and analyzes data from deployed agents. It is responsible for processing logs, triggering alerts, and managing agent configurations.
*   **Wazuh Agent:** A lightweight, multi-purpose agent deployed on monitored endpoints (servers, cloud instances, containers, etc.). It collects system logs, file integrity data, configuration information, and other security-relevant events.
*   **Wazuh Dashboard (Kibana):** The web-based user interface for visualizing data, analyzing alerts, managing agents, and monitoring the overall security posture of the environment.

Installation is typically performed using a pre-built Virtual Appliance (OVA), which simplifies the deployment of the Wazuh server and dashboard.

### 2. Log Analysis & File Integrity Monitoring (FIM)

**Log Analysis:**
Wazuh excels at collecting, correlating, and analyzing log data from a wide variety of sources, including operating systems, applications, and network devices. The Wazuh agent reads logs and forwards them to the server, where they are processed by a ruleset to detect security events, misconfigurations, and policy violations. Key log analysis activities include:

*   **SSH Log Monitoring:** Detecting successful and failed login attempts, brute-force attacks, and other suspicious SSH activity.
*   **Windows Event Log Monitoring:** Analyzing Windows event logs for security-related events such as user account changes, logon successes and failures, and system-level changes.
*   **System Log Monitoring:** General monitoring of system logs (e.g., `syslog` on Linux) for a wide range of security indicators.

**File Integrity Monitoring (FIM):**
The FIM module in Wazuh is used to monitor changes to the filesystem. It creates a baseline of file checksums and attributes and then periodically scans for modifications. FIM is critical for detecting unauthorized file changes that may indicate a security breach, such as malware installation or unauthorized modification of critical system files.

*   **Real-time Monitoring:** The `realtime` option in the FIM configuration leverages kernel-level integration to detect file changes as they happen.
*   **`whodata`:** This feature provides details on *who* made a file change, including the user and process responsible.

### 3. Rootkit Detection

Wazuh includes a `rootcheck` module designed to detect the presence of rootkits and other system anomalies. It performs a series of checks, including:

*   **Scanning for known rootkit signatures.**
*   **Checking for hidden processes and files.**
*   **Monitoring for promiscuous network interfaces.**
*   **Verifying the integrity of system binaries.**

Alerts from `rootcheck` can indicate a compromised system where an attacker is attempting to hide their presence.

### 4. Threat Intelligence & Malware Detection Integration

Wazuh can be integrated with external threat intelligence sources and malware detection tools to enhance its detection capabilities.

*   **VirusTotal Integration:** Wazuh can automatically submit file hashes to the VirusTotal API to check if they are associated with known malware. This is often configured to trigger on FIM events (e.g., when a new file is created or modified).
*   **Custom Threat Intelligence Feeds:** Wazuh can ingest custom lists of Indicators of Compromise (IoCs), such as malicious IP addresses, URLs, or file hashes. These lists are used to create rules that trigger alerts when a matching IoC is observed in log data or other events.

### 5. Active Response

Wazuh's active response module allows it to automatically execute scripts or commands on an agent in response to specific triggers. This enables automated remediation of certain threats. Common use cases include:

*   **Blocking Malicious IP Addresses:** Automatically adding a malicious IP address to a firewall blocklist when a brute-force attack is detected.
*   **Removing Malware:** Executing a script to delete a file that has been identified as malware by VirusTotal.
*   **Restarting Services:** Automatically restarting a critical service if it is terminated unexpectedly.

Active response configurations are defined in the `ossec.conf` file on the Wazuh server and can be triggered by specific rule IDs.

### 6. Building SOC Dashboards

The Wazuh Dashboard (Kibana) is a powerful tool for creating custom Security Operations Center (SOC) dashboards. These dashboards can provide a high-level overview of the security posture of the environment and allow security analysts to quickly identify and investigate threats. Key visualizations include:

*   **Top Alerting Agents:** Identifying the endpoints that are generating the most security alerts.
*   **Alert Level Distribution:** Visualizing the severity of alerts to prioritize investigation.
*   **Recent Events Table:** A real-time view of the latest security events.
*   **FIM Events:** A dedicated view of file integrity monitoring alerts.
*   **Threat Intelligence Hits:** Visualizing alerts triggered by threat intelligence feeds.

By combining these visualizations, analysts can create a comprehensive and customized view of their security environment.
