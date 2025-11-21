# Threat Intelligence & Malware Detection Guide: Summary

This document summarizes how to integrate Wazuh with threat intelligence feeds and malware detection capabilities, specifically using VirusTotal.

## 1. Building IOC Files for Threat Intelligence

This section describes how to create a Python script that automatically extracts Indicators of Compromise (IOCs) from Wazuh alerts and adds them to dedicated IOC files.

1.  **Create the IOC Builder Script:**
    -   Create a Python script named `ioc-builder.py` in `/var/ossec/active-response/bin/`.
    -   This script reads alert data and extracts potential IOCs like `srcip`, `url`, and file hashes (`md5`).
    -   It then writes these IOCs to dedicated list files (e.g., `/var/ossec/etc/lists/mal-ip-list`, `/var/ossec/etc/lists/mal-url-list`).

2.  **Configure Active Response to Run the Script:**
    -   In the `/var/ossec/etc/ossec.conf` file on the Wazuh server, configure an active response block to automatically execute the `ioc-builder.py` script.
    -   This execution is triggered when rules with specific IDs are fired (e.g., `5712` for brute-force, `87105` for VirusTotal alerts, `31103` for web server errors).

    **Example `ossec.conf` Snippet:**
    ```xml
    <command>
      <name>ioc-builder</name>
      <executable>ioc-builder.py</executable>
    </command>

    <active-response>
      <disabled>no</disabled>
      <command>ioc-builder</command>
      <location>server</location>
      <rules_id>5712,87105,31103</rules_id>
    </active-response>
    ```

3.  **Create a Custom Decoder and Rules:**
    -   A custom decoder (`local_decoder.xml`) is needed to parse the output of the `ioc-builder.py` script.
    -   Custom rules (`local_rules.xml`) are created to generate alerts when the script adds a new IOC to a list or when a previously seen IOC is detected.

    **Example Custom Rules:**
    ```xml
    <group name="iocs,">
      <rule id="111001" level="5">
        <if_sid>111000</if_sid>
        <field name="ioc_not_found">^True$</field>
        <description>Suspicious IoC "$(ioc)" added to "$(ioc_file)".</description>
      </rule>
      <rule id="111002" level="5" ignore="60">
        <if_sid>111000</if_sid>
        <field name="ioc_not_found">^False$</field>
        <description>Suspicious IoC "$(ioc)" already found in "$(ioc_file)".</description>
      </rule>
    </group>
    ```

4.  **Restart the Wazuh Manager:**
    -   Restart the manager to apply the new configuration: `sudo systemctl restart wazuh-manager`.

## 2. Malware Detection with FIM and VirusTotal

This section describes how to configure Wazuh to scan for malicious files using the VirusTotal integration.

### Configuration on the Ubuntu Endpoint (Agent)

1.  **Configure FIM:**
    -   In the agent's `/var/ossec/etc/ossec.conf` file, configure the `<syscheck>` block to monitor a directory in real-time (e.g., the `/root` directory).
    -   Example: `<directories realtime="yes">/root</directories>`
2.  **Install `jq`:**
    -   Install the `jq` utility, which is used by the active response script to process JSON data.
    -   `sudo apt-get install jq`
3.  **Create the `remove-threat.sh` Script:**
    -   Create an active response script at `/var/ossec/active-response/bin/remove-threat.sh`. This script is responsible for deleting a file that VirusTotal has identified as malicious.
4.  **Restart the Agent:**
    -   Restart the `wazuh-agent` to apply the changes.

### Configuration on the Wazuh Server

1.  **Add Rules for FIM Changes:**
    -   In `/var/ossec/etc/rules/local_rules.xml`, add rules to detect file changes in the monitored directory (`/root`).

    **Example Rules for `/root` directory:**
    ```xml
    <group name="syscheck,pci_dss_11.5,nist_800_53_SI.7,">
      <rule id="100200" level="7">
        <if_sid>550</if_sid>
        <field name="file">/root</field>
        <description>File modified in /root directory.</description>
      </rule>
      <rule id="100201" level="7">
        <if_sid>554</if_sid>
        <field name="file">/root</field>
        <description>File added to /root directory.</description>
      </rule>
    </group>
    ```

2.  **Configure VirusTotal Integration:**
    -   In `/var/ossec/etc/ossec.conf`, add an `<integration>` block for VirusTotal.
    -   Provide your VirusTotal API key.
    -   Specify the rule IDs that should trigger a VirusTotal scan (e.g., `100200` and `100201`).

    **Example VirusTotal Integration:**
    ```xml
    <integration>
      <name>virustotal</name>
      <api_key>YOUR_VIRUS_TOTAL_API_KEY</api_key>
      <rule_id>100200,100201</rule_id>
      <alert_format>json</alert_format>
    </integration>
    ```

3.  **Configure Active Response to Remove Threats:**
    -   In `ossec.conf`, configure an active response to run the `remove-threat.sh` script when VirusTotal flags a file as malicious (rule `87105`).

    **Example Active Response Block:**
    ```xml
    <command>
      <name>remove-threat</name>
      <executable>remove-threat.sh</executable>
      <timeout_allowed>no</timeout_allowed>
    </command>
    <active-response>
      <command>remove-threat</command>
      <location>local</location>
      <rules_id>87105</rules_id>
    </active-response>
    ```

4.  **Add Rules for Active Response Results:**
    -   In `local_rules.xml`, add rules to confirm whether the active response script successfully removed the threat.

5.  **Restart the Manager:**
    -   Restart the `wazuh-manager` to apply all changes.

### Attack Emulation

-   Download a test malware file (like the EICAR test file) to the monitored directory on the agent.
-   **Expected Alerts:**
    1.  A "File added" alert (e.g., rule `100201`).
    2.  A VirusTotal alert (`87105`) indicating the file is malicious.
    3.  An active response alert (`100092`) confirming the file was removed.
    4.  A "File deleted" alert (`553`).
-   You can also navigate to **Management > CDB lists** in the dashboard to see the MD5 hash of the malware added to the `mal-md5-list`.
