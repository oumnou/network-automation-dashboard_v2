// Enhanced script.js for Cisco Integration
// ===============================
// Utility Functions
// ===============================
function logActivity(msg) {
  const logPanel = document.getElementById("activityLog");
  if (logPanel) {
    logPanel.innerHTML += `[${new Date().toLocaleTimeString()}] ${msg}<br>`;
    logPanel.scrollTop = logPanel.scrollHeight;
  }
}

async function fetchJSON(url, opts = {}) {
  try {
    const res = await fetch(url, opts);
    const data = await res.json();
    
    if (!res.ok) {
      throw new Error(data.error || `HTTP ${res.status}: ${res.statusText}`);
    }
    return data;
  } catch (error) {
    logActivity(`❌ API Error: ${error.message}`);
    throw error;
  }
}

// ===============================
// Enhanced Network Scanner for Cisco
// ===============================
document.getElementById("scanNetworkBtn").addEventListener("click", async () => {
  const range = document.getElementById("networkRange").value.trim();
  
  logActivity(`🔍 Starting Cisco device scan...`);
  document.getElementById("scanNetworkBtn").disabled = true;
  document.getElementById("scanNetworkBtn").textContent = "⏳ Scanning Cisco Devices...";

  try {
    // Use targeted scan for known Cisco IPs if no range specified or default range
    const scanType = (!range || range === "10.10.20.0/24") ? "known_only" : "full";
    
    const data = await fetchJSON("/api/scan/", { 
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ 
        network: range,
        scan_type: scanType
      })
    });

    displayScanResults(data);
    
  } catch (error) {
    logActivity(`❌ Cisco scan failed: ${error.message}`);
  } finally {
    document.getElementById("scanNetworkBtn").disabled = false;
    document.getElementById("scanNetworkBtn").textContent = "🔍 Scan for Cisco Devices";
  }
});

// Add quick scan button for known devices
function createQuickScanButton() {
  const controlPanel = document.querySelector('.control-panel');
  const quickScanBtn = document.createElement('button');
  quickScanBtn.className = 'btn btn-success';
  quickScanBtn.innerHTML = '⚡ Quick Scan';
  quickScanBtn.title = 'Scan known Cisco device IPs only';
  quickScanBtn.onclick = quickScanKnownDevices;
  controlPanel.insertBefore(quickScanBtn, controlPanel.firstChild);
}

async function quickScanKnownDevices() {
  logActivity("⚡ Quick scanning known Cisco devices...");
  
  try {
    const data = await fetchJSON("/api/scan/known", { method: "POST" });
    displayScanResults(data);
    
    if (data.validation) {
      const val = data.validation;
      logActivity(`📊 Topology: ${val.found_count}/${val.expected_count} devices found`);
      if (val.missing_devices.length > 0) {
        logActivity(`⚠️ Missing: ${val.missing_devices.join(', ')}`);
      }
    }
  } catch (error) {
    logActivity(`❌ Quick scan failed: ${error.message}`);
  }
}

function displayScanResults(data) {
  const scanResultsDiv = document.getElementById("scanResults");
  scanResultsDiv.innerHTML = "";
  scanResultsDiv.style.display = "block";

  if (!data.results || data.results.length === 0) {
    scanResultsDiv.innerHTML = "<p>No Cisco devices found or accessible.</p>";
    logActivity("⚠️ No accessible Cisco devices detected");
    return;
  }

  // Add scan summary
  if (data.scan_info) {
    const summary = document.createElement("div");
    summary.style.cssText = "background: rgba(34, 197, 94, 0.1); border: 1px solid rgba(34, 197, 94, 0.3); border-radius: 6px; padding: 12px; margin-bottom: 16px; font-size: 13px;";
    summary.innerHTML = `
      <strong>Scan Results:</strong> ${data.scan_info.authenticated_count}/${data.scan_info.total_found} devices accessible 
      (${data.scan_info.duration}s, ${data.scan_info.scan_type})
    `;
    scanResultsDiv.appendChild(summary);
  }

  data.results.forEach(device => {
    const item = document.createElement("div");
    item.className = "scan-result-item";
    
    // Enhanced display for Cisco devices
    const deviceIcon = getCiscoDeviceIcon(device);
    const roleColor = getRoleColor(device.role_hint);
    const statusIcon = device.authenticated ? "✅" : "❌";
    
    item.innerHTML = `
      <div style="display: flex; justify-content: space-between; align-items: center;">
        <div style="flex: 1;">
          <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 6px;">
            <span style="font-size: 18px;">${deviceIcon}</span>
            <strong style="color: ${roleColor};">${device.hostname}</strong>
            <span style="font-size: 12px;">${statusIcon}</span>
          </div>
          <div style="color: #9ca3af; font-size: 13px; line-height: 1.4;">
            <div><strong>IP:</strong> ${device.ip} | <strong>Role:</strong> ${device.role_hint}</div>
            <div><strong>Model:</strong> ${device.model} | <strong>IOS:</strong> ${device.ios_version}</div>
            <div><strong>Interfaces:</strong> ${device.interface_count} | <strong>Uptime:</strong> ${device.uptime}</div>
          </div>
        </div>
        <div style="display: flex; flex-direction: column; gap: 4px;">
          <button class="btn btn-sm" onclick="addCiscoDevice('${device.ip}', ${JSON.stringify(device).replace(/'/g, "&apos;")})">
            ➕ Add
          </button>
          <button class="btn btn-sm btn-secondary" onclick="viewDeviceDetails('${device.ip}')">
            👁️ View
          </button>
        </div>
      </div>
    `;
    
    item.style.cssText = `
      cursor: pointer; padding: 16px; margin: 8px 0; 
      background: rgba(31, 41, 59, 0.8); border-radius: 8px; 
      border: 1px solid rgba(71, 85, 105, 0.5); 
      transition: all 0.2s ease;
    `;

    item.onmouseenter = () => item.style.backgroundColor = "rgba(71, 85, 105, 0.3)";
    item.onmouseleave = () => item.style.backgroundColor = "rgba(31, 41, 59, 0.8)";

    scanResultsDiv.appendChild(item);
  });

  logActivity(`✅ Cisco scan complete: ${data.results.length} devices found`);
}

function getCiscoDeviceIcon(device) {
  if (device.role_hint === "core") return "🏛️";
  if (device.role_hint === "distribution") return "🏢";
  if (device.role_hint === "access") return "🏠";
  return "🌐";
}

function getRoleColor(role) {
  switch(role) {
    case "core": return "#60a5fa";
    case "distribution": return "#a78bfa";
    case "access": return "#34d399";
    default: return "#9ca3af";
  }
}

async function addCiscoDevice(ip, deviceData) {
  const device = typeof deviceData === 'string' ? JSON.parse(deviceData) : deviceData;
  
  document.getElementById("newIP").value = ip;
  document.getElementById("newHostname").value = device.hostname || `cisco-${ip.split('.').pop()}`;
  document.getElementById("newRole").value = device.role_hint || "access";
  document.getElementById("newDeviceType").value = "cisco";

  logActivity(`➡️ Auto-filled form with ${device.hostname} (${ip})`);
  
  // Auto-submit if device looks good
  if (device.authenticated && device.hostname !== "unknown") {
    document.getElementById("addSwitchForm").dispatchEvent(new Event('submit'));
  }
}

async function viewDeviceDetails(ip) {
  logActivity(`👁️ Viewing details for ${ip}...`);
  
  try {
    const data = await fetchJSON(`/api/scan/single`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ip })
    });
    
    if (data.result) {
      showCiscoDeviceDetails(data.result);
    }
  } catch (error) {
    logActivity(`❌ Failed to get device details: ${error.message}`);
  }
}

function showCiscoDeviceDetails(device) {
  // Update the switch details panel with comprehensive Cisco info
  document.getElementById("switchName").textContent = device.hostname || device.ip;
  document.getElementById("switchIP").textContent = device.ip;
  document.getElementById("switchRole").textContent = device.role_hint || "access";
  
  // Update status with more detail
  const statusDiv = document.getElementById("switchStatus");
  const statusSpan = statusDiv.querySelector("span");
  if (statusSpan) {
    statusSpan.textContent = device.authenticated ? "Online" : "Offline";
    statusDiv.className = `status-indicator ${device.authenticated ? "status-healthy" : "status-critical"}`;
  }
  
  // Show Cisco-specific metrics
  document.getElementById("cpuValue").textContent = "N/A"; // Could be enhanced with SNMP
  document.getElementById("memoryValue").textContent = "N/A";
  document.getElementById("tempValue").textContent = "N/A";
  document.getElementById("interfacesValue").textContent = device.interface_count || "—";
  
  // Update form for editing
  document.getElementById("newHostname").value = device.hostname || "";
  document.getElementById("newIP").value = device.ip || "";
  document.getElementById("newRole").value = device.role_hint || "access";
  document.getElementById("newDeviceType").value = "cisco";
  
  logActivity(`📋 Viewing Cisco device: ${device.hostname} (${device.model}, IOS ${device.ios_version})`);
}

// ===============================
// Enhanced Add/Update Switch for Cisco
// ===============================
document.getElementById("addSwitchForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const hostname = document.getElementById("newHostname").value.trim();
  const ip = document.getElementById("newIP").value.trim();
  const role = document.getElementById("newRole").value;
  const deviceType = document.getElementById("newDeviceType").value;

  if (!hostname || !ip) {
    logActivity("⚠️ Hostname and IP are required");
    return;
  }

  // Enhanced IP validation
  if (!validateIPAddress(ip)) {
    logActivity("⚠️ Invalid IP address format");
    return;
  }

  try {
    const data = await fetchJSON("/api/switch/", { 
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ 
        hostname, 
        ip, 
        role,
        device_type: deviceType,
        status: "up" // Assume up if we're adding it
      })
    });

    if (data.ok) {
      logActivity(`✅ Cisco device saved: ${hostname} (${ip}, ${role})`);
      document.getElementById("addSwitchForm").reset();
      document.getElementById("newDeviceType").value = "cisco"; // Default to Cisco
      await loadTopology();
    }
  } catch (error) {
    logActivity(`❌ Failed to save Cisco device: ${error.message}`);
  }
});

// ===============================
// Enhanced Topology Visualization
// ===============================
async function loadTopology() {
  try {
    const data = await fetchJSON("/api/switch/");
    const container = document.getElementById("network-topology");

    if (!data || data.length === 0) {
      container.innerHTML = `
        <div style="display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100%; color: #9ca3af; text-align: center;">
          <div style="font-size: 24px; margin-bottom: 10px;">🏢</div>
          <div>No Cisco switches configured</div>
          <div style="font-size: 14px; margin-top: 5px;">Use the scanner to discover Cisco devices</div>
        </div>
      `;
      return;
    }

    // Enhanced node creation for Cisco devices
    const nodes = data.map(sw => {
      const roleColors = {
        "core": "#60a5fa",
        "distribution": "#a78bfa", 
        "access": "#34d399"
      };
      
      const roleIcons = {
        "core": "🏛️",
        "distribution": "🏢",
        "access": "🏠"
      };
      
      return {
        id: sw.ip,
        label: `${roleIcons[sw.role] || "🌐"}\n${sw.hostname || sw.ip}`,
        shape: "dot",
        size: sw.role === "core" ? 40 : sw.role === "distribution" ? 35 : 30,
        font: { 
          color: '#e5e7eb', 
          size: 11,
          multi: true
        },
        color: {
          background: roleColors[sw.role] || "#9ca3af",
          border: "#1f2937",
          highlight: {
            background: roleColors[sw.role] || "#9ca3af",
            border: "#ffffff"
          }
        },
        title: `<b>${sw.hostname}</b><br/>
                 IP: ${sw.ip}<br/>
                 Role: ${sw.role}<br/>
                 Type: ${sw.device_type || 'cisco'}<br/>
                 Status: ${sw.status || 'unknown'}`
      };
    });

    // Create hierarchical topology based on your Cisco network
    const edges = createCiscoTopologyEdges(data);

    const options = {
      physics: { 
        enabled: true,
        stabilization: { iterations: 150 },
        hierarchicalRepulsion: {
          nodeDistance: 120,
          centralGravity: 0.3,
          springLength: 100,
          springConstant: 0.01,
          damping: 0.09
        }
      },
      edges: { 
        arrows: { to: { enabled: false } },
        color: { color: '#475569' },
        width: 2,
        smooth: {
          type: 'continuous',
          forceDirection: 'vertical',
          roundness: 0.4
        }
      },
      interaction: {
        hover: true,
        tooltipDelay: 200,
        selectConnectedEdges: false
      },
      layout: {
        hierarchical: {
          enabled: true,
          direction: 'UD',
          sortMethod: 'directed',
          nodeSpacing: 150,
          levelSeparation: 180,
          shakeTowards: 'roots'
        }
      }
    };

    const network = new vis.Network(container, { nodes, edges }, options);

    network.on("click", (params) => {
      if (params.nodes.length > 0) {
        const ip = params.nodes[0];
        showSwitchDetails(ip, data);
      }
    });

    logActivity(`🔄 Cisco topology loaded: ${data.length} devices`);
    
  } catch (error) {
    logActivity(`❌ Failed to load Cisco topology: ${error.message}`);
    const container = document.getElementById("network-topology");
    container.innerHTML = `
      <div style="display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100%; color: #ef4444; text-align: center;">
        <div style="font-size: 24px; margin-bottom: 10px;">⚠️</div>
        <div>Failed to load topology</div>
        <div style="font-size: 14px; margin-top: 5px;">${error.message}</div>
      </div>
    `;
  }
}

function createCiscoTopologyEdges(switches) {
  const edges = [];
  
  // Find devices by role
  const coreDevices = switches.filter(sw => sw.role === "core");
  const distDevices = switches.filter(sw => sw.role === "distribution"); 
  const accessDevices = switches.filter(sw => sw.role === "access");
  
  // Connect distribution to core (based on your topology)
  if (coreDevices.length > 0 && distDevices.length > 0) {
    const core1 = coreDevices.find(sw => sw.hostname.includes("Core1"));
    if (core1) {
      distDevices.forEach(dist => {
        edges.push({ from: core1.ip, to: dist.ip });
      });
    }
  }
  
  // Connect access devices to distribution (based on your topology)
  if (distDevices.length > 0 && accessDevices.length > 0) {
    const dist1 = distDevices.find(sw => sw.hostname.includes("Dist1"));
    const dist2 = distDevices.find(sw => sw.hostname.includes("Dist2"));
    
    accessDevices.forEach(access => {
      if (access.hostname.includes("End1") || access.hostname.includes("End2")) {
        // Connect End1 and End2 to Dist1
        if (dist1) edges.push({ from: dist1.ip, to: access.ip });
      } else if (access.hostname.includes("End3") || access.hostname.includes("End4")) {
        // Connect End3 and End4 to Dist2
        if (dist2) edges.push({ from: dist2.ip, to: access.ip });
      }
    });
  }
  
  return edges;
}

// ===============================
// Enhanced Backup for Cisco
// ===============================
document.getElementById("backupBtn").addEventListener("click", async () => {
  const ip = document.getElementById("switchIP").textContent;
  if (!ip || ip === "—") {
    logActivity("⚠️ No Cisco device selected for backup");
    return;
  }

  // Get Cisco credentials
  const credentials = await promptForCiscoCredentials();
  if (!credentials) {
    logActivity("⚠️ Backup cancelled (missing credentials)");
    return;
  }

  logActivity(`💾 Starting Cisco config backup for ${ip}...`);
  document.getElementById("backupBtn").disabled = true;
  document.getElementById("backupBtn").textContent = "⏳ Backing up...";

  try {
    const data = await fetchJSON("/api/backup/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ip,
        username: credentials.username,
        password: credentials.password,
        enable_password: credentials.enable_password,
        device_type: "cisco"
      })
    });

    if (data.ok) {
      logActivity(`✅ Cisco backup complete: ${data.meta.bytes} bytes saved`);
      logActivity(`📁 Config saved to: ${data.backup_dir}`);
    } else {
      logActivity(`❌ Cisco backup failed: ${data.error}`);
    }
  } catch (error) {
    logActivity(`❌ Cisco backup failed: ${error.message}`);
  } finally {
    document.getElementById("backupBtn").disabled = false;
    document.getElementById("backupBtn").textContent = "💾 Backup Config";
  }
});

async function promptForCiscoCredentials() {
  // Use default Cisco sandbox credentials
  const username = prompt("Enter Cisco username:", "developer");
  if (!username) return null;
  
  const password = prompt("Enter Cisco password:", "C1sco12345");
  if (!password) return null;
  
  const enable_password = prompt("Enter enable password:", "C1sco12345");
  
  return { username, password, enable_password };
}

// ===============================
// Enhanced Utility Functions
// ===============================
function validateIPAddress(ip) {
  const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  return ipRegex.test(ip);
}

function validateNetworkRange(range) {
  const cidrRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/([0-9]|[1-2][0-9]|3[0-2])$/;
  return cidrRegex.test(range);
}

// ===============================
// Cisco-Specific Features
// ===============================
async function testCiscoConnectivity(ip) {
  logActivity(`🔍 Testing Cisco connectivity to ${ip}...`);
  
  try {
    const result = await fetchJSON(`/api/scan/single`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ip })
    });
    
    if (result.result && result.result.authenticated) {
      logActivity(`✅ Cisco device ${ip} is accessible: ${result.result.hostname}`);
      return result.result;
    } else {
      logActivity(`❌ Cisco device ${ip} not accessible: ${result.result?.error || 'Unknown error'}`);
      return null;
    }
  } catch (error) {
    logActivity(`❌ Connectivity test failed for ${ip}: ${error.message}`);
    return null;
  }
}

// Add topology validation function
async function validateCiscoTopology() {
  logActivity("🔍 Validating Cisco topology...");
  
  try {
    const data = await fetchJSON("/api/scan/topology/validate");
    const validation = data.validation;
    
    logActivity(`📊 Topology Status: ${validation.found_count}/${validation.expected_count} devices found`);
    
    if (validation.topology_valid) {
      logActivity("✅ Cisco topology matches expected layout");
    } else {
      logActivity("⚠️ Topology differs from expected layout");
      
      if (validation.missing_devices.length > 0) {
        logActivity(`❌ Missing devices: ${validation.missing_devices.join(', ')}`);
      }
      
      const roles = validation.role_distribution;
      logActivity(`📋 Found: ${roles.core} core, ${roles.distribution} dist, ${roles.access} access`);
    }
    
    return validation;
  } catch (error) {
    logActivity(`❌ Topology validation failed: ${error.message}`);
    return null;
  }
}

// ===============================
// Enhanced Button Handlers
// ===============================
document.getElementById("refreshBtn").addEventListener("click", () => {
  logActivity("🔄 Manual topology refresh triggered");
  loadTopology();
});

document.getElementById("clearLogBtn").addEventListener("click", () => {
  document.getElementById("activityLog").innerHTML = "";
  logActivity("[LOG] Activity log cleared");
});

document.getElementById("exportBtn").addEventListener("click", async () => {
  try {
    const data = await fetchJSON("/api/switch/");
    if (!data || data.length === 0) {
      logActivity("⚠️ No Cisco topology data to export");
      return;
    }

    const exportData = {
      timestamp: new Date().toISOString(),
      network_type: "cisco_sandbox",
      switches: data,
      total_count: data.length,
      role_summary: {
        core: data.filter(sw => sw.role === "core").length,
        distribution: data.filter(sw => sw.role === "distribution").length,
        access: data.filter(sw => sw.role === "access").length
      }
    };

    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `cisco-topology-${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    logActivity(`📤 Cisco topology exported: ${data.length} devices`);
  } catch (error) {
    logActivity(`❌ Export failed: ${error.message}`);
  }
});

// ===============================
// Delete Switch Handler
// ===============================
document.getElementById("deleteBtn").addEventListener("click", async () => {
  const ip = document.getElementById("newIP").value.trim();
  if (!ip) {
    logActivity("⚠️ Enter an IP address to delete");
    return;
  }

  if (!confirm(`Are you sure you want to delete the Cisco device at ${ip}?`)) {
    return;
  }

  try {
    const data = await fetchJSON(`/api/switch/${ip}`, { method: "DELETE" });
    if (data.ok) {
      logActivity(`✅ Cisco device ${ip} deleted from topology`);
      document.getElementById("addSwitchForm").reset();
      document.getElementById("newDeviceType").value = "cisco";
      await loadTopology();
    }
  } catch (error) {
    logActivity(`❌ Failed to delete Cisco device: ${error.message}`);
  }
});

// ===============================
// Enhanced Switch Details Display
// ===============================
async function showSwitchDetails(ip, switchData = null) {
  try {
    const sw = switchData ? switchData.find(s => s.ip === ip) : await fetchJSON(`/api/switch/${ip}`);
    
    if (!sw) {
      logActivity(`❌ Switch details not found for ${ip}`);
      return;
    }

    // Update switch details panel with Cisco-specific info
    document.getElementById("switchName").textContent = sw.hostname || ip;
    document.getElementById("switchIP").textContent = sw.ip || "—";
    document.getElementById("switchRole").textContent = (sw.role || "access").toUpperCase();

    // Update status with better visual indication
    const statusDiv = document.getElementById("switchStatus");
    const statusSpan = statusDiv.querySelector("span");
    if (statusSpan) {
      const status = sw.status || "unknown";
      statusSpan.textContent = status.charAt(0).toUpperCase() + status.slice(1);
      
      // Update status indicator color
      statusDiv.className = `status-indicator ${
        status === "up" ? "status-healthy" : 
        status === "down" ? "status-critical" : "status-warning"
      }`;
    }

    // Update form with switch data for editing
    document.getElementById("newHostname").value = sw.hostname || "";
    document.getElementById("newIP").value = sw.ip || "";
    document.getElementById("newRole").value = sw.role || "access";
    document.getElementById("newDeviceType").value = sw.device_type || "cisco";

    logActivity(`📋 Viewing Cisco device: ${sw.hostname} (${ip})`);
  } catch (error) {
    logActivity(`❌ Failed to load switch details: ${error.message}`);
  }
}

// ===============================
// Keyboard Shortcuts
// ===============================
document.addEventListener('keydown', (e) => {
  if (e.ctrlKey || e.metaKey) {
    switch(e.key) {
      case 'r':
        e.preventDefault();
        loadTopology();
        break;
      case 's':
        e.preventDefault();
        document.getElementById("scanNetworkBtn").click();
        break;
      case 'q':
        e.preventDefault();
        quickScanKnownDevices();
        break;
      case 'e':
        e.preventDefault();
        document.getElementById("exportBtn").click();
        break;
      case 't':
        e.preventDefault();
        validateCiscoTopology();
        break;
    }
  }
});

// ===============================
// Input Validation
// ===============================
document.getElementById("newIP").addEventListener('blur', (e) => {
  const ip = e.target.value.trim();
  if (ip && !validateIPAddress(ip)) {
    e.target.style.borderColor = '#ef4444';
    logActivity("⚠️ Invalid IP address format");
  } else {
    e.target.style.borderColor = '#334155';
  }
});

document.getElementById("networkRange").addEventListener('blur', (e) => {
  const range = e.target.value.trim();
  if (range && !validateNetworkRange(range)) {
    e.target.style.borderColor = '#ef4444';
    logActivity("⚠️ Invalid network range format (use CIDR notation)");
  } else {
    e.target.style.borderColor = '#334155';
  }
});

// ===============================
// Initialization and Startup
// ===============================
window.onload = () => {
  logActivity("[INIT] Cisco Network Dashboard loaded successfully");
  logActivity("[INFO] Ready to scan and manage Cisco devices");
  logActivity("[TIP] Use Ctrl+Q for quick scan, Ctrl+T for topology validation");
  
  // Set default network range for Cisco sandbox
  document.getElementById("networkRange").value = "10.10.20.0/24";
  document.getElementById("newDeviceType").value = "cisco";
  
  // Add quick scan button
  createQuickScanButton();
  
  // Load existing topology
  loadTopology();
  
  // Optional: Start with a quick scan of known devices
  // setTimeout(quickScanKnownDevices, 2000);
};