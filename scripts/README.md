# Scripts

This directory contains proof-of-concept (PoC) scripts used in the Wazuh lab exercises.

## wazuh-ransomware-poc.py

This Python script is designed to simulate a ransomware attack for the purpose of testing Wazuh's File Integrity Monitoring (FIM) capabilities. It contains functions to:
1.  Create a directory of dummy files.
2.  Encrypt all files in a directory and delete the originals.
3.  Decrypt the files to restore them.

### **WARNING**

This script performs destructive actions (file encryption and deletion). It is retained for archival and educational purposes only.

**DO NOT RUN THIS SCRIPT** on any production, development, or otherwise important system. Use only in a dedicated, isolated lab environment that you are prepared to rebuild.
