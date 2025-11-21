# Detecting Ransomware with FIM: Summary

This document summarizes a proof-of-concept for detecting ransomware-like behavior using Wazuh's File Integrity Monitoring (FIM) module. The simulation uses a Python script to mimic a ransomware attack by encrypting files in a directory.

**Note:** The PoC script (`wazuh-ransomware-poc.py`) is retained in the `scripts/` directory for archival purposes only. **DO NOT RUN THIS SCRIPT.**

## PoC Theory and Behavior

The core idea is to monitor a directory for rapid, widespread file modifications and deletions, which are characteristic of a ransomware attack.

### 1. Environment Preparation

-   A test directory is created on the target agent (e.g., `/home/vagrant/test`).
-   The Wazuh agent's `ossec.conf` is configured to monitor this directory using the `syscheck` (FIM) module.
-   The `whodata` option is enabled in the configuration. This allows the Wazuh agent to report which user and process are responsible for file changes.

**Example `ossec.conf` Snippet:**
```xml
<syscheck>
  <directories check_all="yes" whodata="yes">/home/vagrant/test</directories>
</syscheck>
```
-   The agent is restarted to apply the new configuration.
-   The PoC script then populates the monitored directory with a number of dummy files and subdirectories to serve as bait.

### 2. Simulating the Attack

-   The `wazuh-ransomware-poc.py` script contains a function that, when executed, simulates a ransomware attack.
-   This function iterates through all files in the monitored directory.
-   For each file, it performs the following actions:
    1.  **Encrypts** the content of the file.
    2.  Writes the encrypted content to a **new file** with an `.encrypted` extension.
    3.  **Deletes** the original, unencrypted file.

### 3. Detection and Expected Alerts

The Wazuh agent, which is monitoring the directory in real-time, detects this flurry of activity and sends alerts to the manager. In the Wazuh dashboard, this behavior generates two main types of FIM alerts:

-   **File added to the system** (Rule ID `554`): This alert is triggered for each new `.encrypted` file that is created.
-   **File deleted** (Rule ID `553`): This alert is triggered for each original file that is removed.

The high volume of these two alerts occurring in rapid succession is a strong indicator of ransomware activity. By monitoring for this pattern, a security analyst can quickly identify a potential attack in progress.

### 4. Custom Rules for Enhanced Detection

To make detection more specific, custom rules can be created in `/var/ossec/etc/rules/local_rules.xml`.

-   A custom rule can be cloned from an existing SSH rule (e.g., rule `5710`) to detect a specific log format.
-   A new rule can be written to trigger on a custom log message, such as "Failed login attempt for user 'testuser'". This allows for more granular alerting based on specific patterns of interest.
-   The `wazuh-logtest` tool can be used to test new rules and decoders without having to generate real log events.
-   By creating custom rules, you can raise the alert level or add more descriptive information to alerts related to suspicious FIM activity, making it easier for analysts to prioritize and respond.
