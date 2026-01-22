NetSpec - WiFi Security Testing Tool

A WiFi penetration testing tool for security professionals to test network security in controlled environments.

Features:
WiFi Network Scanner: Automatically detects nearby WiFi networks with signal strength indicators
Evil Twin Attack: Creates clone access points to capture credentials
Deauthentication: Sends targeted deauth packets to test network resilience
Credential Capture: Stores captured WiFi passwords persistently
Web-Based Interface: Clean, hacker-style web interface for remote management
SPIFFS Storage: Credentials are saved to internal filesystem and survive reboots
Serial Console: Full control and monitoring via serial interface

Important Notes
⚠️ When Twin AP is active:

The Admin interface (http://192.168.4.1:8080) is NOT ACCESSIBLE
You can only access the captive portal for credential capture
To view captured data, you must:
Stop the Twin AP from Serial Monitor (send 't' command)
OR restart the ESP8266
Reconnect to the Admin AP (NetSpec-Admin)
Access Admin interface at http://192.168.4.1:8080


Hardware Requirements:
ESP8266 (NodeMCU or similar)
USB cable for power and programming

Installation:
Install Arduino IDE
Install ESP8266 board package
Clone this repository
Open NetSpec.ino in Arduino IDE
Select board: NodeMCU 1.0 (ESP-12E Module)
Set Flash Size: 4MB (FS:2MB OTA:~1019KB)
Upload to ESP8266

First Use:
Connect to Serial Monitor at 115200 baud
ESP will create WiFi network: NetSpec-Admin
Password: SecureTest123
Open browser: http://192.168.4.1:8080
Use the web interface to scan networks and start tests

Workflow:
Normal Operation (Admin Mode)
Connect to NetSpec-Admin WiFi
Access http://192.168.4.1:8080
Scan networks and select target
Start Twin AP or Deauth attacks

During Twin AP Operation
Admin interface is inaccessible

Target devices see fake AP with security update page
Credentials are captured and saved automatically
Monitor via Serial Monitor only
After Capturing Credentials
Stop Twin AP via Serial Monitor (send 't' command)
OR restart ESP8266
Reconnect to NetSpec-Admin WiFi
Access http://192.168.4.1:8080 to view captured data

Usage:
Web Interface (Admin Mode Only)
Scan: Discover nearby WiFi networks
Controls: Start/stop deauth and twin AP attacks
Networks: Select target networks from scan results
Captured: View stored credentials with timestamps
File Management: View and download captured data

Serial Commands:
t - Toggle Twin AP (stop to regain admin access)
d - Dump all captured credentials
f - Check filesystem status
s - Manual save to file
l - Show file contents
c - Clear all captured data

Security Notice:
⚠️ IMPORTANT: This tool is for:
Security research and education
Testing your own networks
Authorized penetration testing

❌ DO NOT USE for:
Attacking networks without permission
Illegal activities
Harassing others

You are responsible for complying with all applicable laws and regulations.

Technical Details:
Built for ESP8266 with Arduino framework
Uses SPIFFS for persistent storage
JSON-based credential storage
Responsive web interface
Real-time network scanning

Troubleshooting:
Admin interface not working?
Twin AP might be active
Stop Twin AP via Serial Monitor (send 't')
Or restart ESP8266
Reconnect to NetSpec-Admin network
No credentials showing after capture?
Credentials save automatically
Check with Serial Monitor command 'd'
Ensure SPIFFS is working (command 'f')

Contributing:
This is a security research tool. Contributions should focus on:
Bug fixes
Security improvements
Documentation
Ethical testing features

License
For educational and authorized security testing purposes only.

Disclaimer: Use responsibly and only on networks you own or have explicit permission to test.
