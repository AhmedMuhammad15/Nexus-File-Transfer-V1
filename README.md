# 🚀 NexusTransfer-Core (V1)
**A Distributed Systems File Manager built with Python**

NexusTransfer-Core is a robust peer-to-peer (P2P) file sharing application designed for local area networks. It leverages low-level socket programming for device discovery and high-speed file transfer, coupled with a professional dark-themed GUI.

---

## 🛠️ Key Technical Features

### 1. Peer-to-Peer Discovery (UDP)
- **Automatic Handshake:** Uses UDP broadcasting on port `50001` with a secure magic message (`SMIU_PROJECT_SECURE_HANDSHAKE`) to detect active peers on the network without manual IP entry.
- **Real-time Updates:** Background threads continuously monitor the network for new devices.

### 2. High-Speed TCP Transfer
- **Reliable Protocols:** Implements a custom TCP handshake for file transfers on port `50002`.
- **Integrity:** Uses an ACK (Acknowledgment) system to ensure the receiver is ready before data packets are streamed.

### 3. Integrated Mobile Hosting (HTTP)
- **Built-in Web Server:** Features an embedded HTTP server on port `8000`, allowing any mobile device with a browser to download files directly via a generated local link.

### 4. Hardware Awareness (WMI/System Calls)
- **USB Monitoring:** Utilizes Windows Management Instrumentation (WMI) via system calls (`wmic`) to auto-detect and manage removable media for offline file backups.

---

## 🏗️ Architecture & Tech Stack

- Language: Python 3.8+
- Concurrency: - `multiprocessing`: Decouples the Backend Engine from the Frontend GUI for zero-lag performance.
  - `threading`: Manages multiple simultaneous listeners (UDP/TCP/HTTP).
- GUI Engine: `Tkinter` (Customized Professional Dark Palette).
- Core Modules: `socket`, `http.server`, `subprocess`, `shutil`.

---

## 🚀 Getting Started

### Prerequisites
- OS: Windows (Required for WMI/USB detection features).
- Python installed on your system.

### Installation & Usage
Follow these steps to get the system running on your local machine:

1. System Requirements
Operating System: Windows 10/11 (Required for WMI system calls and USB detection).

Python Version: Python 3.8 or higher.

Network: All devices must be connected to the same Local Area Network (LAN/Wi-Fi).

2. Setup
Clone the repository to your local directory:
git clone https://github.com/AhmedMuhammad15/Nexus-File-Transfer-V1.git

4. Execution
Run the application using the standard Python interpreter:
python nexus_transfer.py

5. Important Notes for Users
Admin Rights: Run your terminal (CMD or PowerShell) as Administrator. This is necessary for the subprocess module to execute wmic commands for detecting removable drives.

Firewall: Ensure your Windows Firewall allows traffic on ports 50001 (UDP), 50002 (TCP), and 8000 (HTTP).

Mobile Access: For the HTTP link to work, your mobile device must be on the same Wi-Fi as your PC.

   ```bash
   git clone [https://github.com/AhmedMuhammad15/Nexus-File-Transfer-V1.git](https://github.com/AhmedMuhammad15/Nexus-File-Transfer-V1.git)
