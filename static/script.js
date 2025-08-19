// static/script.js
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
// Network Scanner
// ===============================
document.getElementById("scanNetworkBtn").addEventListener("click", async () => {
  const range = document.getElementById("networkRange").value.trim();
  if (!range) {
    logActivity("⚠️ Please enter a network range");
    return;
  }
  
  logActivity(`🔍 Scanning ${range}...`);
  document.getElementById("scanNetworkBtn").disabled = true;
  document.getElementById("scanNetworkBtn").textContent = "⏳ Scanning...";

  try {
    const data = await fetchJSON("/api/scan/", { 
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ network: range })
    });

    const scanResultsDiv = document.getElementById("scanResults");
    scanResultsDiv.innerHTML = "";
    scanResultsDiv.style.display = "block";

    if (!data.results || data.results.length === 0) {
      scanResultsDiv.innerHTML = "<p>No devices found with SSH access.</p>";
      logActivity("⚠️ No SSH-accessible devices detected");
      return;
    }

    data.results.forEach(device => {
      const item = document.createElement("div");
      item.className = "scan-result-item";
      
      // Better bridge display parsing
      let bridgeDisplay = device.bridge;
      let deviceIcon = "🔧"; // Default icon
      
      if (device.bridge.includes("OVS-Core")) {
        deviceIcon = "🏛️";
        bridgeDisplay = device.bridge;
      } else if (device.bridge.includes("OVS-Distribution")) {
        deviceIcon = "🏢";
        bridgeDisplay = device.bridge;
      } else if (device.bridge.includes("OVS-Access")) {
        deviceIcon = "🏠";
        bridgeDisplay = device.bridge;
      } else if (device.bridge.includes("OVS-Switch")) {
        deviceIcon = "🌐";
        bridgeDisplay = device.bridge;
      } else if (device.bridge.startsWith("linux-")) {
        deviceIcon = "🐧";
        bridgeDisplay = device.bridge.replace("linux-", "Linux: ");
      } else if (device.bridge === "ovs-no-bridges") {
        deviceIcon = "⚠️";
        bridgeDisplay = "OVS (No Bridges)";
      } else if (device.bridge === "unknown") {
        deviceIcon = "❓";
        bridgeDisplay = "Unknown Device";
      }
      
      const portsDisplay = device.open_ports ? device.open_ports.join(", ") : "N/A";
      
      item.innerHTML = `
        <div style="display: flex; justify-content: space-between; align-items: center;">
          <div>
            <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 4px;">
              <span style="font-size: 16px;">${deviceIcon}</span>
              <b>${bridgeDisplay}</b>
            </div>
            <div style="color: #9ca3af; font-size: 13px;">
              IP: ${device.ip} | Status: ${device.status} | Ports: ${portsDisplay}
            </div>
          </div>
          <button class="btn btn-sm" onclick="autoFillDevice('${device.ip}', '${bridgeDisplay}', '${device.bridge}')">
            ➕ Add
          </button>
        </div>
      `;
      item.style.cursor = "pointer";
      item.style.padding = "12px";
      item.style.margin = "6px 0";
      item.style.backgroundColor = "#1f2937";
      item.style.borderRadius = "8px";
      item.style.border = "1px solid #374151";
      item.style.transition = "background-color 0.2s";

      item.onmouseenter = () => item.style.backgroundColor = "#374151";
      item.onmouseleave = () => item.style.backgroundColor = "#1f2937";

      item.onclick = (e) => {
        if (e.target.tagName !== 'BUTTON') {
          autoFillDevice(device.ip, bridgeDisplay, device.bridge);
        }
      };

      scanResultsDiv.appendChild(item);
    });

    logActivity(`✅ Scan complete: ${data.results.length} devices found`);
  } catch (error) {
    logActivity(`❌ Scan failed: ${error.message}`);
  } finally {
    document.getElementById("scanNetworkBtn").disabled = false;
    document.getElementById("scanNetworkBtn").textContent = "🔍 Scan for Switches";
  }
});

function autoFillDevice(ip, displayName, bridgeType) {
  document.getElementById("newIP").value = ip;
  
  // Smart hostname generation based on bridge type
  let hostname = displayName;
  if (bridgeType.includes("OVS-Core")) {
    hostname = `core-sw-${ip.split('.').slice(-1)[0]}`;
  } else if (bridgeType.includes("OVS-Distribution")) {
    hostname = `dist-sw-${ip.split('.').slice(-1)[0]}`;
  } else if (bridgeType.includes("OVS-Access")) {
    hostname = `access-sw-${ip.split('.').slice(-1)[0]}`;
  } else if (bridgeType.includes("OVS-Switch")) {
    hostname = `ovs-sw-${ip.split('.').slice(-1)[0]}`;
  } else if (bridgeType.startsWith("linux-")) {
    hostname = `linux-${ip.replace(/\./g, '-')}`;
  } else {
    hostname = `device-${ip.replace(/\./g, '-')}`;
  }
  document.getElementById("newHostname").value = hostname;

  // Smart role detection based on bridge info
  if (bridgeType.includes("OVS-Core") || displayName.toLowerCase().includes("core")) {
    document.getElementById("newRole").value = "core";
  } else if (bridgeType.includes("OVS-Distribution") || displayName.toLowerCase().includes("dist")) {
    document.getElementById("newRole").value = "distribution";
  } else {
    document.getElementById("newRole").value = "access";
  }

  // Smart device type detection
  if (bridgeType.includes("OVS") || bridgeType.includes("ovs")) {
    document.getElementById("newDeviceType").value = "ovs";
  } else if (bridgeType.startsWith("linux")) {
    document.getElementById("newDeviceType").value = "linux";
  } else {
    document.getElementById("newDeviceType").value = "cisco";
  }

  logActivity(`➡️ Auto-filled form with ${hostname} (${ip})`);
}

// ===============================
// Add / Update Switch
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

  // Basic IP validation
  const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (!ipRegex.test(ip)) {
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
        device_type: deviceType 
      })
    });

    if (data.ok) {
      logActivity(`✅ Switch saved: ${hostname} (${ip}, ${role})`);
      document.getElementById("addSwitchForm").reset();
      document.getElementById("newDeviceType").value = "ovs"; // Reset to default
      await loadTopology();
    } else {
      logActivity(`❌ Failed to save switch: ${data.error}`);
    }
  } catch (error) {
    logActivity(`❌ Failed to save switch: ${error.message}`);
  }
});

// ===============================
// Delete Switch
// ===============================
document.getElementById("deleteBtn").addEventListener("click", async () => {
  const ip = document.getElementById("newIP").value.trim();
  if (!ip) {
    logActivity("⚠️ Enter an IP address to delete");
    return;
  }

  if (!confirm(`Are you sure you want to delete the switch at ${ip}?`)) {
    return;
  }

  try {
    const data = await fetchJSON(`/api/switch/${ip}`, { method: "DELETE" });
    if (data.ok) {
      logActivity(`✅ Switch ${ip} deleted`);
      document.getElementById("addSwitchForm").reset();
      await loadTopology();
    }
  } catch (error) {
    logActivity(`❌ Failed to delete switch: ${error.message}`);
  }
});

// ===============================
// Backup Switch Config
// ===============================
document.getElementById("backupBtn").addEventListener("click", async () => {
  const ip = document.getElementById("switchIP").textContent;
  if (!ip || ip === "—") {
    logActivity("⚠️ No switch selected for backup");
    return;
  }

  // Create a modal-like prompt
  const credentials = await promptForCredentials();
  if (!credentials) {
    logActivity("⚠️ Backup cancelled (missing credentials)");
    return;
  }

  logActivity(`💾 Starting backup for ${ip}...`);
  document.getElementById("backupBtn").disabled = true;
  document.getElementById("backupBtn").textContent = "⏳ Backing up...";

  try {
    // Get device type from current switch data
    const switches = await fetchJSON("/api/switch/");
    const currentSwitch = switches.find(sw => sw.ip === ip);
    const deviceType = currentSwitch?.device_type || "ovs";

    const data = await fetchJSON("/api/backup/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ip,
        username: credentials.username,
        password: credentials.password,
        device_type: deviceType
      })
    });

    if (data.ok) {
      logActivity(`✅ Backup complete: ${data.meta.bytes} bytes saved (${data.engine})`);
    } else {
      logActivity(`❌ Backup failed: ${data.error}`);
    }
  } catch (error) {
    logActivity(`❌ Backup failed: ${error.message}`);
  } finally {
    document.getElementById("backupBtn").disabled = false;
    document.getElementById("backupBtn").textContent = "💾 Backup";
  }
});

async function promptForCredentials() {
  const username = prompt("Enter SSH username:", "kali");
  if (!username) return null;
  
  const password = prompt("Enter SSH password:", "kali");
  if (!password) return null;
  
  return { username, password };
}

// ===============================
// Refresh / Topology Visualization
// ===============================
async function loadTopology() {
  try {
    const data = await fetchJSON("/api/switch/");
    const container = document.getElementById("network-topology");

    if (!data || data.length === 0) {
      container.innerHTML = `
        <div style="display: flex; flex-direction: column; align-items: center; justify-content: center; height: 100%; color: #9ca3af; text-align: center;">
          <div style="font-size: 24px; margin-bottom: 10px;">🌐</div>
          <div>No switches configured</div>
          <div style="font-size: 14px; margin-top: 5px;">Use the scanner to discover switches</div>
        </div>
      `;
      return;
    }

    const nodes = data.map(sw => ({
      id: sw.ip,
      label: sw.hostname || sw.ip,
      shape: "dot",
      size: 30,
      font: { color: '#e5e7eb', size: 12 },
      color: {
        background: sw.role === "core" ? "#60a5fa" : 
                   sw.role === "distribution" ? "#a78bfa" : "#34d399",
        border: "#1f2937"
      },
      title: `${sw.hostname}\nIP: ${sw.ip}\nRole: ${sw.role}\nType: ${sw.device_type || 'unknown'}`
    }));

    const edges = [];
    
    // Create a hierarchical topology
    const coreNodes = nodes.filter(n => data.find(sw => sw.ip === n.id && sw.role === "core"));
    const distNodes = nodes.filter(n => data.find(sw => sw.ip === n.id && sw.role === "distribution"));
    const accessNodes = nodes.filter(n => data.find(sw => sw.ip === n.id && sw.role === "access"));

    // Connect distribution switches to core switches
    if (coreNodes.length > 0 && distNodes.length > 0) {
      coreNodes.forEach(core => {
        distNodes.forEach(dist => {
          edges.push({ from: core.id, to: dist.id });
        });
      });
    }

    // Connect access switches to distribution switches (or core if no dist)
    const parentNodes = distNodes.length > 0 ? distNodes : coreNodes;
    if (parentNodes.length > 0) {
      accessNodes.forEach((access, i) => {
        const parentIndex = i % parentNodes.length;
        edges.push({ from: parentNodes[parentIndex].id, to: access.id });
      });
    }

    const options = {
      physics: { 
        enabled: true,
        stabilization: { iterations: 100 },
        barnesHut: {
          gravitationalConstant: -8000,
          springConstant: 0.001,
          springLength: 200
        }
      },
      edges: { 
        arrows: { to: { enabled: false } },
        color: { color: '#374151' },
        width: 2
      },
      interaction: {
        hover: true,
        tooltipDelay: 200
      },
      layout: {
        hierarchical: {
          enabled: true,
          direction: 'UD',
          sortMethod: 'directed',
          nodeSpacing: 150,
          levelSeparation: 200
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

    logActivity(`🔄 Topology refreshed: ${data.length} switches loaded`);
    
  } catch (error) {
    logActivity(`❌ Failed to load topology: ${error.message}`);
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

async function showSwitchDetails(ip, switchData = null) {
  try {
    const sw = switchData ? switchData.find(s => s.ip === ip) : await fetchJSON(`/api/switch/${ip}`);
    
    if (!sw) {
      logActivity(`❌ Switch details not found for ${ip}`);
      return;
    }

    // Update switch details panel
    document.getElementById("switchName").textContent = sw.hostname || ip;
    document.getElementById("switchIP").textContent = sw.ip || "—";
    document.getElementById("switchRole").textContent = sw.role || "—";

    // Update status indicator
    const statusDiv = document.getElementById("switchStatus");
    const statusSpan = statusDiv.querySelector("span");
    if (statusSpan) {
      statusSpan.textContent = sw.status || "unknown";
    }

    // Update form with switch data for editing
    document.getElementById("newHostname").value = sw.hostname || "";
    document.getElementById("newIP").value = sw.ip || "";
    document.getElementById("newRole").value = sw.role || "access";
    if (document.getElementById("newDeviceType")) {
      document.getElementById("newDeviceType").value = sw.device_type || "ovs";
    }

    // Mock health metrics (replace with real data when available)
    document.getElementById("cpuValue").textContent = "—";
    document.getElementById("memoryValue").textContent = "—";
    document.getElementById("tempValue").textContent = "—";
    document.getElementById("interfacesValue").textContent = "—";

    logActivity(`📋 Viewing details for ${sw.hostname} (${ip})`);
  } catch (error) {
    logActivity(`❌ Failed to load switch details: ${error.message}`);
  }
}

// ===============================
// Additional Button Handlers
// ===============================
document.getElementById("refreshBtn").addEventListener("click", () => {
  logActivity("🔄 Manual refresh triggered");
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
      logActivity("⚠️ No topology data to export");
      return;
    }

    const exportData = {
      timestamp: new Date().toISOString(),
      switches: data,
      total_count: data.length
    };

    const blob = new Blob([JSON.stringify(exportData, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `network-topology-${new Date().toISOString().split('T')[0]}.json`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);

    logActivity(`📤 Topology exported: ${data.length} switches`);
  } catch (error) {
    logActivity(`❌ Export failed: ${error.message}`);
  }
});

// ===============================
// Auto-refresh and Error Recovery
// ===============================
let autoRefreshInterval = null;

function startAutoRefresh(intervalMs = 60000) {
  if (autoRefreshInterval) {
    clearInterval(autoRefreshInterval);
  }
  
  autoRefreshInterval = setInterval(() => {
    logActivity("🔄 Auto-refresh triggered");
    loadTopology();
  }, intervalMs);
}

function stopAutoRefresh() {
  if (autoRefreshInterval) {
    clearInterval(autoRefreshInterval);
    autoRefreshInterval = null;
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
      case 'e':
        e.preventDefault();
        document.getElementById("exportBtn").click();
        break;
    }
  }
});

// ===============================
// Network Status Monitoring
// ===============================
async function checkNetworkStatus() {
  try {
    const response = await fetch('/api/logs/tail?n=1');
    return response.ok;
  } catch (error) {
    return false;
  }
}

// ===============================
// Enhanced Error Handling
// ===============================
window.addEventListener('error', (e) => {
  logActivity(`❌ JavaScript Error: ${e.message}`);
});

window.addEventListener('unhandledrejection', (e) => {
  logActivity(`❌ Promise Rejection: ${e.reason}`);
});

// ===============================
// Responsive Design Helpers
// ===============================
function adjustLayoutForScreen() {
  const dashboard = document.querySelector('.dashboard');
  if (window.innerWidth < 1200) {
    dashboard.style.gridTemplateColumns = '1fr';
    dashboard.style.gap = '12px';
  } else {
    dashboard.style.gridTemplateColumns = '1fr 360px';
    dashboard.style.gap = '16px';
  }
}

window.addEventListener('resize', adjustLayoutForScreen);

// ===============================
// Init and Startup
// ===============================
window.onload = () => {
  logActivity("[INIT] Dashboard loaded successfully");
  logActivity("[INFO] Ready to scan network and manage switches");
  logActivity("[TIP] Use Ctrl+R to refresh, Ctrl+S to scan, Ctrl+E to export");
  
  adjustLayoutForScreen();
  loadTopology();
  
  // Start auto-refresh (optional - uncomment if desired)
  // startAutoRefresh(60000); // 60 seconds
};

// ===============================
// Additional Utility Functions
// ===============================
function validateIPAddress(ip) {
  const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  return ipRegex.test(ip);
}

function validateNetworkRange(range) {
  const cidrRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/([0-9]|[1-2][0-9]|3[0-2])$/;
  return cidrRegex.test(range);
}

// Add input validation
document.getElementById("newIP").addEventListener('blur', (e) => {
  const ip = e.target.value.trim();
  if (ip && !validateIPAddress(ip)) {
    e.target.style.borderColor = '#ef4444';
    logActivity("⚠️ Invalid IP address format");
  } else {
    e.target.style.borderColor = '#22314a';
  }
});

document.getElementById("networkRange").addEventListener('blur', (e) => {
  const range = e.target.value.trim();
  if (range && !validateNetworkRange(range)) {
    e.target.style.borderColor = '#ef4444';
    logActivity("⚠️ Invalid network range format (use CIDR notation)");
  } else {
    e.target.style.borderColor = '#22314a';
  }
});