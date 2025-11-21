# Building a SOC Dashboard Guide: Summary

This document outlines the steps to create a Security Operations Center (SOC) dashboard in Wazuh using the visualization capabilities of Kibana.

## Step 1: Access Kibana Visualizations

1.  Log in to the Wazuh dashboard.
2.  Navigate to **Explore > Visualize** from the main menu.
3.  Ensure the `wazuh-alerts-*` index pattern is selected for all visualizations.

## Step 2: Create Visualization for Top Alerting Agents

This visualization displays the top 5 agents generating the most alerts.

1.  **Create Visualization:**
    -   Click **Create new visualization** and select **Pie**.
2.  **Configure Metrics:**
    -   Under **Metrics**, select **Count** to aggregate the total number of alerts.
3.  **Configure Buckets:**
    -   Add a **Bucket > Split Slices > Terms** aggregation.
    -   Select the **Field:** `agent.name`.
    -   Set **Size** to 5.
    -   Set **Order by** to `Count`, `Descending`.
4.  **Save Visualization:**
    -   Click **Save** and name it `Top_5_Alerting_Agents`.

## Step 3: Create Visualization for Alert Levels

This visualization shows the distribution of alerts by severity level.

1.  **Create Visualization:**
    -   Click **Create new visualization** and select **Horizontal Bar**.
2.  **Configure Metrics:**
    -   Under **Metrics**, select **Count** for the Y-axis.
3.  **Configure Buckets:**
    -   Add a **Bucket > X-Axis > Terms** aggregation.
    -   Select the **Field:** `rule.level`.
    -   Set **Size** to 13 (to cover levels 3-15).
    -   Set **Order by** to `Count`, `Descending`.
4.  **Save Visualization:**
    -   Click **Save** and name it `Alert_Levels_Distribution`.

## Step 4: Create Visualization for Recent Events

This visualization displays a data table of the most recent security events.

1.  **Create Visualization:**
    -   Click **Create new visualization** and select **Data Table**.
2.  **Configure Metrics:**
    -   Under **Metrics**, select **Count**.
3.  **Configure Buckets:**
    -   Add a **Bucket > Split Rows > Date Histogram** aggregation. Select the **Field:** `timestamp` and set **Minimum Interval** to `Auto` or `Hourly`.
    -   Add additional **Split Rows > Terms** aggregations for:
        -   `agent.name`
        -   `rule.description`
        -   `rule.level`
    -   Set **Size** to 10 for each to limit the number of recent events shown.
4.  **Save Visualization:**
    -   Click **Save** and name it `Recent_Events_Table`.

## Step 5: Create the SOC Dashboard

1.  **Navigate to Dashboard:**
    -   Go to **Explore > Dashboard** and click **Create new dashboard**.
2.  **Add Visualizations:**
    -   Click **Add** and select the visualizations created earlier:
        -   `Top_5_Alerting_Agents`
        -   `Alert_Levels_Distribution`
        -   `Recent_Events_Table`
    -   Arrange the visualizations on the dashboard as desired.
3.  **Configure Dashboard Settings:**
    -   Set the dashboard time range (e.g., `Last 24 hours`).
    -   Enable **Auto-refresh** (e.g., every 5 minutes).
4.  **Save Dashboard:**
    -   Click **Save** and name it `SOC_Dashboard`.
    -   Optionally, add filters (e.g., `rule.level:>3`) to focus on higher-severity alerts.

## Attack Chain Simulation Example

This section provides a theoretical overview of simulating an attack chain to test the dashboard.

### 1. Brute Force Attack

-   **Simulation:** Repeatedly attempt to SSH into a Linux host with an invalid user.
-   **Expected Alerts:** Wazuh triggers rules `5710` (SSH brute force) or `5720` (multiple failed logins).
-   **Detection:** Use the filter `rule.id:5710 OR rule.id:5720` in the Security Events dashboard to view the alerts.

### 2. Local Privilege Escalation

-   **Simulation:** Attempt to gain unauthorized root access, for example, by using `sudo -u nobody /bin/bash` or modifying the `/etc/passwd` file.
-   **Expected Alerts:** FIM rules `550`/`554` (file changes) or rule `5100` (sudo misuse).
-   **Detection:** Use the filter `syscheck.path:/etc/passwd` or the relevant rule IDs to find the alerts.

### 3. Create and Exfiltrate Sensitive File

-   **Simulation:** Create a file with sensitive data and then transfer it off the host using a tool like `scp`.
-   **Expected Alerts:** FIM rules `550`/`553`/`554` (file added/modified/deleted). A custom rule may be needed to detect the exfiltration itself.
-   **Detection:** Use the filter `syscheck.path:/tmp/sensitive.txt` (or the path of the created file) to view the FIM alerts.
