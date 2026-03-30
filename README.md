# Official [Cyber Range](http://joshmadakor.tech/cyber-range) Project

<img width="400" src="https://github.com/user-attachments/assets/44bac428-01bb-4fe9-9d85-96cba7698bee" alt="Tor Logo with the onion and a crosshair on it"/>

# Threat Hunt Report: Unauthorized TOR Usage
- [Scenario Creation](https://github.com/cyberwizard-lab/threat-hunting-scenario-tor/blob/main/Threat_Hunt_Event_(TOR%20Usage).md)

## Platforms and Languages Leveraged
- Windows 11 Virtual Machines (Microsoft Azure)
- EDR Platform: Microsoft Defender for Endpoint
- Kusto Query Language (KQL)
- Tor Browser

##  Scenario

Management suspects that some employees may be using TOR browsers to bypass network security controls because recent network logs show unusual encrypted traffic patterns and connections to known TOR entry nodes. Additionally, there have been anonymous reports of employees discussing ways to access restricted sites during work hours. The goal is to detect any TOR usage and analyze related security incidents to mitigate potential risks. If any use of TOR is found, notify management.

### High-Level TOR-Related IoC Discovery Plan

- **Check `DeviceFileEvents`** for any `tor(.exe)` or `firefox(.exe)` file events.
- **Check `DeviceProcessEvents`** for any signs of installation or usage.
- **Check `DeviceNetworkEvents`** for any signs of outgoing connections over known TOR ports.

---

## Steps Taken

### 1. Searched the `DeviceFileEvents` Table

Searched for any file that had the string "tor" in it and discovered what looks like the user "wizard" downloaded a TOR installer, did something that resulted in many TOR-related files being copied to the desktop, and the creation of a file called `tor-shopping-list.txt` on the desktop at `Mar 26, 2026 4:43:20 PM`.

**Query used to locate events:**

```kql
DeviceFileEvents  
| where DeviceName == "cyberwizard"  
| where FileName contains "tor"  
| where Timestamp >= ago(7d)
| order by Timestamp desc  
| project Timestamp, DeviceName, ActionType, FileName, FolderPath, SHA256, Account = InitiatingProcessAccountName
```
<img width="1346" height="558" alt="image" src="https://github.com/user-attachments/assets/9eeebb6d-a2b9-47f4-a18b-3e2665698fa5" />

---

### 2. Searched the `DeviceProcessEvents` Table

Searched for any `ProcessCommandLine` that contained the string "tor-browser". Based on the logs returned, at `Mar 26, 2026 4:23:56 PM`, an employee on the "cyberwizard" device ran the file `tor-browser-windows-x86_64-portable-14.0.1.exe` from their Downloads folder, using a command that triggered a silent installation.

**Query used to locate event:**

```kql
DeviceProcessEvents
| where DeviceName == "cyberwizard"  
| where ProcessCommandLine contains "tor-browser"  
| project Timestamp, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
```
<img width="1382" height="720" alt="image" src="https://github.com/user-attachments/assets/6b41f559-b5c4-41fd-964a-50bf83af1b1b" />

---

### 3. Searched the `DeviceProcessEvents` Table for TOR Browser Execution

Searched for any indication that user "wizard" actually opened the TOR browser. There was evidence that they did open it at `Mar 26, 2026 4:29:23 PM`. There were several other instances of `firefox.exe` (TOR) as well as `tor.exe` spawned afterwards.

In the screenshot below, note that the application "firefox.exe" is in the folder "Tor Browser", indicating it is actually TOR. You could also search [where FolderPath contains "Tor Browser"] to get similar results.

**Query used to locate events:**

```kql
DeviceProcessEvents
| where DeviceName == "cyberwizard"  
| where AccountName == "wizard"
| where ActionType == "ProcessCreated"
| where FileName has_any ("tor.exe", "tor-browser.exe", "firefox.exe") 
| project Timestamp, AccountName, ActionType, FileName, FolderPath, SHA256, ProcessCommandLine
| sort by Timestamp desc
```
<img width="1335" height="680" alt="image" src="https://github.com/user-attachments/assets/c356b18c-8dcc-4463-9eea-017c71fb2388" />

---

### 4. Searched the `DeviceNetworkEvents` Table for TOR Network Connections

I Searched for any indication the TOR browser was used to establish a connection using any of the known TOR ports. At `Mar 26, 2026 4:26:33 PM`, an employee on the "cyberwizard" device successfully established a connection to the remote IP address `94[.]16[.]122[.]61` on port `9001`. The connection was initiated by the process `tor.exe`, located in the folder `c:\users\wizard\desktop\tor browser\browser\torbrowser\tor\`. This was followed by multiple connections to sites over port 9001, with a single loopback connection to port 9150.

**Query used to locate events:**

```kql
DeviceNetworkEvents  
| where DeviceName == "cyberwizard"  
| where InitiatingProcessAccountName != "system"  
| where InitiatingProcessFileName in ("tor.exe", "firefox.exe")  
| where RemotePort in ("9001", "9030", "9040", "9050", "9051", "9150", "80", "443")  
| project Timestamp, DeviceName, InitiatingProcessAccountName, ActionType, RemoteIP, RemotePort, RemoteUrl, InitiatingProcessFileName, InitiatingProcessFolderPath  
| order by Timestamp desc
```
<img width="1338" height="233" alt="image" src="https://github.com/user-attachments/assets/572c941a-d81c-4abf-9865-2a2a0f35e12e" />

---

## Chronological Event Timeline 

## Chronological Event Timeline

### 1. Process Execution – TOR Installer Initiated

- **Timestamp:** `2026-03-26 16:23:56`  
- **Device:** `cyberwizard`  
- **User:** `wizard`  
- **Event:** Execution of the TOR installer `tor-browser-windows-x86_64-portable-14.0.1.exe` from the Downloads directory.  
- **Action:** Process creation detected indicating user-initiated execution.  
- **Command Line:** Silent installation triggered via command-line arguments.  
- **File Path:**  
  `C:\Users\wizard\Downloads\tor-browser-windows-x86_64-portable-14.0.1.exe`

---

### 2. Network Activity – Initial TOR Connection Established

- **Timestamp:** `2026-03-26 16:26:33`  
- **Device:** `cyberwizard`  
- **User:** `wizard`  
- **Event:** Outbound connection to known TOR network infrastructure.  
- **Action:** Successful network connection detected.  
- **Remote IP:** `94.16.122.61`  
- **Remote Port:** `9001` *(TOR relay port)*  
- **Process:** `tor.exe`  
- **Process Path:**  
  `C:\Users\wizard\Desktop\Tor Browser\Browser\TorBrowser\Tor\tor.exe`

---

### 3. Process Execution – TOR Browser Launch

- **Timestamp:** `2026-03-26 16:29:23`  
- **Device:** `cyberwizard`  
- **User:** `wizard`  
- **Event:** TOR Browser launched successfully.  
- **Action:** Multiple process creation events observed.  

**Processes Identified:**
- `firefox.exe` *(TOR Browser wrapper)*  
- `tor.exe` *(TOR service)*  

- **Observation:** Execution path confirms usage of the TOR Browser bundle rather than standard Firefox.  
- **File Path:**  
  `C:\Users\wizard\Desktop\Tor Browser\Browser\TorBrowser\Tor\`

---

### 4. Network Activity – Continued TOR Communications

- **Timestamp Range:** `2026-03-26 16:26:33 – 16:30:XX`  
- **Device:** `cyberwizard`  
- **User:** `wizard`  
- **Event:** Multiple outbound connections over TOR-associated ports.  
- **Action:** Sustained encrypted communications detected.  

**Ports Observed:**
- `9001` *(TOR relay)*  
- `9150` *(local SOCKS proxy loopback)*  

- **Observation:** Behaviour consistent with an active TOR browsing session.  

---

### 5. File System Activity – TOR Artefact Creation

- **Timestamp:** `2026-03-26 16:43:20`  
- **Device:** `cyberwizard`  
- **User:** `wizard`  
- **Event:** Creation of TOR-related file on desktop.  
- **Action:** File creation detected.  
- **File Name:** `tor-shopping-list.txt`  
- **File Path:**  
  `C:\Users\wizard\Desktop\tor-shopping-list.txt`  

- **Observation:** Indicates potential user interaction or note-taking during TOR session.  

---

---

## Summary

The user "wizard" on the "cyberwizard" machine initiated and completed the installation of the TOR browser. They proceeded to launch the browser, establish connections within the TOR network, and created various files related to TOR on their desktop, including a file named `tor-shopping-list.txt`. This sequence of activities indicates that the user actively installed, configured, and used the TOR browser, likely for anonymous browsing purposes, with possible documentation in the form of the "shopping list" file.

---

## Response Taken

TOR usage was confirmed on the endpoint `cyberwizard` by the user `wizard`. The device was isolated, and the user's direct manager was notified.

---
