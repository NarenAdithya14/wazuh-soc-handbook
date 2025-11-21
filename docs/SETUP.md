# Wazuh Setup Guide: Summary

This document provides a summary of the steps for setting up a Wazuh environment using the pre-built Virtual Appliance (OVA).

## 1. Wazuh Server Installation (OVA)

### Step 1: Download the Wazuh Virtual Appliance (OVA)
-   Download the pre-built Wazuh OVA file (e.g., version 4.9.2) from the official Wazuh website.

### Step 2: System Requirements
-   **Host System:** 64-bit with hardware virtualization (BIOS/UEFI) enabled.
-   **Virtualization Platform:** VirtualBox, VMware, or Hyper-V.
-   **Default VM Configuration:**
    -   CPU: 4 cores
    -   RAM: 8 GB
    -   Storage: 50 GB
    *Note: These resources can be adjusted based on needs.*

### Step 3: Import the OVA File
1.  Open your virtualization platform (e.g., VMware).
2.  Go to `File > Open` and select the downloaded `.ova` file.
3.  Name the VM (e.g., "Wazuh Server") and choose a location for the VM files.
4.  Adjust VM resources (RAM, CPU) and network adapter settings (e.g., NAT or Bridged) as needed.

### Step 4: Start and Access the VM
1.  Power on the imported VM.
2.  Log in with the default credentials:
    -   **Username:** `wazuh-user`
    -   **Password:** `wazuh`
3.  Find the VM's IP address by running the command: `ip a`

### Step 5: Access the Wazuh Dashboard
1.  Open a web browser on a machine on the same network.
2.  Navigate to `https://<wazuh_server_ip>`.
3.  If you encounter a privacy warning, accept the risk and proceed.
4.  Log in to the dashboard with the default credentials:
    -   **Username:** `admin`
    -   **Password:** `admin`

## 2. Wazuh Agent Deployment

### Step 1: Install Wazuh Agent on Linux (Debian/Ubuntu)

1.  **Add the Wazuh Repository:**
    ```bash
    echo "deb https://packages.wazuh.com/4.x/apt/ stable main" | sudo tee /etc/apt/sources.list.d/wazuh.list
    wget -qO - https://packages.wazuh.com/key/GPG-KEY-WAZUH | sudo apt-key add -
    sudo apt-get update
    ```

2.  **Install the Agent:**
    ```bash
    sudo apt-get install wazuh-agent
    ```

3.  **Configure the Agent:**
    -   Edit the agent configuration file at `/var/ossec/etc/ossec.conf`.
    -   Point the agent to the Wazuh manager's IP address within the `<client><server><address>` block.

    **Example `ossec.conf` Snippet:**
    ```xml
    <client>
      <server>
        <address>YOUR_WAZUH_MANAGER_IP</address>
        <port>1514</port>
        <protocol>tcp</protocol>
      </server>
    </client>
    ```

4.  **Start the Agent:**
    ```bash
    sudo systemctl enable wazuh-agent
    sudo systemctl start wazuh-agent
    ```

### Step 2: Install Wazuh Agent on Windows

1.  **Download the Installer:**
    -   Download the Windows agent installer (`.exe`) from the official Wazuh repository.

2.  **Run the Installer:**
    -   Execute the installer and follow the wizard, providing the Wazuh manager IP when prompted.

3.  **Verify Agent Status:**
    -   Open a command prompt and check the service status: `net start WazuhSvc`

### Step 3: Connect Agent to Manager

1.  **Register the Agent (on the Wazuh Manager):**
    -   Use the `manage_agents` tool to register a new agent, for example: `sudo /var/ossec/bin/manage_agents -i <agent-id>`

2.  **Restart the Wazuh Manager:**
    -   Apply the changes by restarting the manager: `sudo systemctl restart wazuh-manager`

3.  **Verify Connection:**
    -   Check the agent's status in the Wazuh dashboard under the "Agents" tab.

## 3. Basic Dashboard Exploration

-   **Security Events:** View and filter alerts.
-   **Agents:** See the status of all connected agents.
-   **File Integrity Monitoring (FIM):** Monitor file changes on endpoints.
-   **Syscheck:** View system integrity alerts.
-   **Vulnerability Detection:** Discover known vulnerabilities in your environment.
