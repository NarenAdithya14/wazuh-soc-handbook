# Rootkit Detection Guide: Summary

This document provides a summary of how to use Wazuh for rootkit detection, detect failed SSH login attempts, and enable active responses.

## 1. Rootkit Detection with Wazuh

The `rootcheck` module in Wazuh is designed to detect rootkits and other system anomalies.

### A. Ensure Rootcheck is Enabled

1.  On the Wazuh agent, edit the configuration file at `/var/ossec/etc/ossec.conf`.
2.  Ensure the `<rootcheck>` block is enabled and configured. A typical configuration runs the scan periodically.

    **Example `ossec.conf` Snippet:**
    ```xml
    <rootcheck>
      <enabled>yes</enabled>
      <frequency>3600</frequency> <!-- every hour -->
    </rootcheck>
    ```

### B. View Results in Wazuh Dashboard

1.  Go to the Wazuh Dashboard.
2.  Navigate to **Modules > Rootcheck**.
3.  Review any alerts. An alert for "Anomaly detected" may indicate a hidden file or process, which could be a sign of a kernel-level rootkit.

## 2. Detect Failed SSH Login Attempts (Brute Force)

### A. Simulate Brute-force SSH Attempts

From any other machine, run a loop to simulate multiple failed SSH login attempts against a host with a Wazuh agent.

**Example Simulation Command:**
```bash
for i in {1..15}; do
  ssh invaliduser@<WAZUH_AGENT_IP> -o StrictHostKeyChecking=no
done
```

### B. View Alerts

1.  Go to the **Wazuh Dashboard > Security Events**.
2.  Use a search query to filter for failed authentication events.
    -   `rule.group:"authentication_failed"`
    -   `rule.id:5710` (attempt to log in with a non-existent user)
    -   `rule.id:5712` (multiple failed SSH login attempts)
3.  You should see alerts for "sshd: authentication failed" or "Multiple failed SSH login attempts".

## 3. Enable Active Responses for IP Blocking

This section describes how to configure Wazuh to automatically block the IP address of an attacker who is attempting a brute-force attack.

### A. Enable Active Response in `ossec.conf`

On the **Wazuh Manager**, edit the `/var/ossec/etc/ossec.conf` file to add an active response configuration.

1.  **Define the Active Response:**
    This block tells Wazuh to execute a command when a specific rule is triggered. In this case, it will block the source IP for 600 seconds (10 minutes) when rule `5712` (SSH brute-force) is triggered.

    ```xml
    <active-response>
      <command>firewall-drop</command>
      <location>local</location>
      <rules_id>5712</rules_id>
      <timeout>600</timeout>
    </active-response>
    ```

2.  **Define the Command:**
    This block defines what the `firewall-drop` command does. It executes a script (`firewall-drop.sh`) and expects the source IP (`srcip`) as an argument.

    ```xml
    <command>
      <name>firewall-drop</name>
      <executable>firewall-drop.sh</executable>
      <expect>srcip</expect>
      <timeout_allowed>yes</timeout_allowed>
    </command>
    ```
    *Note: The `firewall-drop.sh` script must exist in `/var/ossec/active-response/bin/`.*

### B. Custom Rule for Blocking Threat Intelligence IPs

You can also use active response to block IPs found in threat intelligence feeds.

1.  **Add a Custom Rule:**
    In `/var/ossec/etc/rules/local_rules.xml`, add a rule that triggers when an IP address is found in a blocklist (e.g., `blacklist-alienvault`).

    ```xml
    <group name="attack,">
      <rule id="100100" level="10">
        <if_group>web|attack|attacks</if_group>
        <list field="srcip" lookup="address_match_key">etc/lists/blacklist-alienvault</list>
        <description>IP address found in AlienVault reputation database.</description>
      </rule>
    </group>
    ```

2.  **Add the `blacklist-alienvault` List to `ossec.conf`:**
    Make sure the ruleset is configured to use the list.

    ```xml
    <ruleset>
      <list>etc/lists/blacklist-alienvault</list>
    </ruleset>
    ```

3.  **Add the Active Response Block:**
    In `ossec.conf`, add a block to trigger `firewall-drop` for your custom rule (`100100`).

    ```xml
    <active-response>
      <disabled>no</disabled>
      <command>firewall-drop</command>
      <location>local</location>
      <rules_id>100100</rules_id>
      <timeout>60</timeout>
    </active-response>
    ```

### C. Restart and Test

1.  Restart the Wazuh manager to apply the changes: `sudo systemctl restart wazuh-manager`.
2.  Trigger the brute-force attack again or simulate traffic from a blacklisted IP.
3.  Check the alerts in the dashboard. You should see an active response alert, and the malicious IP should be blocked.
