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
    if (!res.ok) {
      throw new Error(`HTTP ${res.status}: ${res.statusText}`);
    }
    return await res.json();
  } catch (error) {
    logActivity(`❌ API Error: ${error.message}`);
    throw error;
  }
}

// ===============================
// Network Scanner
// ===============================
document.getElementById("scanNetworkBtn").addEventListener("click", async () => {
  const range = document.getElementById("networkRange").value;
  logActivity(`🔍 Scanning ${range}...`);

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
      scanResultsDiv.innerHTML = "<p>No switches found.</p>";
      logActivity("⚠️ No switches detected");
      return;
    }

    data.results.forEach(sw => {
      const item = document.createElement("div");
      item.className = "scan-result-item";
      item.innerHTML = `<b>${sw.bridge}</b> (${sw.ip}) - Status: ${sw.status}`;
      item.style.cursor = "pointer";
      item.style.padding = "8px";
      item.style.margin = "4px 0";
      item.style.backgroundColor = "#1f2937";
      item.style.borderRadius = "6px";

      item.onclick = () => {
        document.getElementById("newHostname").value = sw.bridge !== "unknown" ? sw.bridge : `switch-${sw.ip.replace(/\./g, '-')}`;
        document.getElementById("newIP").value = sw.ip;

        // Smart role detection
        if (sw.bridge.toLowerCase().includes("core")) {
          document.getElementById("newRole").value = "core";
        } else if (sw.bridge.toLowerCase().includes("dist")) {
          document.getElementById("newRole").value = "distribution";
        } else {
          document.getElementById("newRole").value = "access";
        }

        logActivity(`➡️ Auto-filled form with ${sw.bridge} (${sw.ip})`);
      };

      scanResultsDiv.appendChild(item);
    });

    logActivity(`✅ Scan complete: ${data.results.length} switches detected`);
  } catch (error) {
    logActivity(`❌ Scan failed: ${error.message}`);
  }
});

// ===============================
// Add / Update Switch
// ===============================
document.getElementById("addSwitchForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const hostname = document.getElementById("newHostname").value;
  const ip = document.getElementById("newIP").value;
  const role = document.getElementById("newRole").value;

  try {
    const data = await fetchJSON("/api/switch/", { 
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ hostname, ip, role })
    });

    if (data.ok) {
      logActivity(`✅ Switch saved: ${hostname} (${ip}, ${role})`);
      document.getElementById("addSwitchForm").reset();
      await loadTopology();
    } else {
      logActivity(`❌ Failed to save switch: ${data.error}`);
    }
  } catch (error) {
    logActivity(`❌ Failed to save switch: ${error.message}`);
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

  const username = prompt("Enter SSH username:") || "kali";
  const password = prompt("Enter SSH password:") || "kali";

  if (!username || !password) {
    logActivity("⚠️ Backup cancelled (missing credentials)");
    return;
  }

  logActivity(`💾 Starting backup for ${ip}...`);

  try {
    const data = await fetchJSON("/api/backup/run", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        ip,
        username,
        password,
        device_type: "ovs"
      })
    });

    if (data.ok) {
      logActivity(`✅ Backup complete: ${data.meta.bytes} bytes saved to ${data.config_path}`);
    } else {
      logActivity(`❌ Backup failed: ${data.error}`);
    }
  } catch (error) {
    logActivity(`❌ Backup failed: ${error.message}`);
  }
});

// ===============================
// Refresh / Topology Visualization
// ===============================
async function loadTopology() {
  try {
    const data = await fetchJSON("/api/switch/");
    const container = document.getElementById("network-topology");

    if (!data || data.length === 0) {
      container.innerHTML = '<div style="display: flex; align-items: center; justify-content: center; height: 100%; color: #9ca3af;">No switches configured. Use the scanner to discover switches.</div>';
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
      }
    }));

    const edges = [];
    
    // Create a simple topology: core -> distribution -> access
    const coreNodes = nodes.filter(n => data.find(sw => sw.ip === n.id && sw.role === "core"));
    const distNodes = nodes.filter(n => data.find(sw => sw.ip === n.id && sw.role === "distribution"));
    const accessNodes = nodes.filter(n => data.find(sw => sw.ip === n.id && sw.role === "access"));

    // Connect distribution switches to core switches
    coreNodes.forEach(core => {
      distNodes.forEach(dist => {
        edges.push({ from: core.id, to: dist.id });
      });
    });

    // Connect access switches to distribution switches (round-robin)
    accessNodes.forEach((access, i) => {
      if (distNodes.length > 0) {
        const distIndex = i % distNodes.length;
        edges.push({ from: distNodes[distIndex].id, to: access.id });
      }
    });

    const options = {
      physics: { 
        enabled: true,
        stabilization: { iterations: 100 }
      },
      edges: { 
        arrows: { to: { enabled: false } },
        color: { color: '#374151' }
      },
      interaction: {
        hover: true
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
    container.innerHTML = '<div style="display: flex; align-items: center; justify-content: center; height: 100%; color: #ef4444;">Failed to load topology</div>';
  }
}

async function showSwitchDetails(ip, switchData = null) {
  try {
    const sw = switchData ? switchData.find(s => s.ip === ip) : await fetchJSON(`/api/switch/${ip}`);
    
    if (!sw) {
      logActivity(`❌ Switch details not found for ${ip}`);
      return;
    }

    document.getElementById("switchName").textContent = sw.hostname || ip;
    document.getElementById("switchIP").textContent = sw.ip || "—";
    document.getElementById("switchRole").textContent = sw.role || "—";

    const statusDiv = document.getElementById("switchStatus");
    const statusSpan = statusDiv.querySelector("span");
    if (statusSpan) {
      statusSpan.textContent = sw.status || "unknown";
    }

    // Mock health metrics (replace with real data if available)
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
document.getElementById("refreshBtn").addEventListener("click", loadTopology);

// Optional: Auto-refresh every 30 seconds
// setInterval(loadTopology, 30000);

// ===============================
// Init
// ===============================
window.onload = () => {
  logActivity("[INIT] Dashboard loaded successfully");
  logActivity("[INFO] Ready to scan network and manage switches");
  loadTopology();
};