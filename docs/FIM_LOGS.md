# Wazuh Log Analysis and FIM Guide: Summary

This document provides a summary of how to perform log analysis and configure File Integrity Monitoring (FIM) in Wazuh.

## 1. Log Analysis

### Step 1: View SSH Logs

1.  **Access Security Events:** Log in to the Wazuh dashboard and navigate to the "Security Events" module.
2.  **Filter for SSH Logs:** Use a query in the search bar to filter for SSH-related events. For example:
    ```
    rule.groups:authentication AND data.srcip:*
    ```
3.  **Review Logs:** Examine the details of the alerts, including the source IP, username, and timestamp for each SSH event.

### Step 2: View Windows Event Logs

1.  **Select Windows Agent:** In the dashboard, go to the "Agents" tab and select a specific Windows agent.
2.  **Navigate to Security Events:** View the security events for the selected agent.
3.  **Filter Windows Events:** Use a query to display only Windows Event Logs. For example:
    ```
    agent.os.platform:windows AND rule.groups:windows
    ```
4.  **Analyze Details:** Review the event details, including the user, event ID, and a description of the event.

### Step 3: View System Logs (Linux)

1.  **Select Linux Agent:** In the dashboard, go to the "Agents" tab and select a Linux agent.
2.  **Navigate to Security Events:** Access the "Security Events" module for that agent.
3.  **Filter System Logs:** Use a query to filter for system-level logs. For example:
    ```
    agent.os.platform:linux AND rule.groups:syslog
    ```
4.  **Review Entries:** Check details such as the process name, log message, and timestamp.

### Step 4: Filter Alerts by Rule Level

1.  **Access Security Events:** Navigate to the "Security Events" module.
2.  **Filter by Rule Level:** Use a query to show alerts of a certain severity. For example, to show high-severity alerts (level 8 or above):
    ```
    rule.level:>7
    ```
3.  **Review Alerts:** Analyze the filtered alerts to identify critical events or patterns.

## 2. File Integrity Monitoring (FIM)

### Step 1: Configure FIM on Sensitive Directories

1.  **Edit Agent Configuration:** On the Wazuh manager, you can edit the agent configuration file `/var/ossec/etc/ossec.conf` or use the centralized configuration feature in the dashboard.

2.  **Add FIM Directory:** Add a `<syscheck>` block to the configuration to specify a directory to monitor. The `realtime="yes"` attribute enables monitoring of file changes as they happen.

    **Example FIM Configuration:**
    ```xml
    <syscheck>
      <directories check_all="yes" realtime="yes">/etc</directories>
    </syscheck>
    ```
    *This example monitors the `/etc` directory on a Linux system. For Windows, you might monitor a directory like `C:\Program Files`.*

3.  **Verify Configuration:** In the Wazuh dashboard, go to the "File Integrity Monitoring" module to confirm that the directory is being monitored. You should see a list of the files in the monitored directory.

### Step 2: Trigger and View FIM Alerts

1.  **Modify a File:** Make a change to a file within the monitored directory to trigger a FIM alert.
2.  **Check FIM Alerts:** In the "File Integrity Monitoring" module of the Wazuh dashboard, look for an alert indicating the file modification.
3.  **Review Alert Details:** Click on the alert to see specific details, such as the modified content, the user who made the change (if `whodata` is enabled), and the checksum of the file before and after the change.
