// ===============================
// Utility Functions
// ===============================
function logActivity(msg) {
  const logPanel = document.getElementById("activityLog");
  logPanel.innerHTML += `[${new Date().toLocaleTimeString()}] ${msg}<br>`;
  logPanel.scrollTop = logPanel.scrollHeight;
}

async function fetchJSON(url, opts = {}) {
  const res = await fetch(url, opts);
  return res.json();
}

// ===============================
// Network Scanner
// ===============================
document.getElementById("scanNetworkBtn").addEventListener("click", async () => {
  const range = document.getElementById("networkRange").value;
  logActivity(`🔍 Scanning ${range}...`);

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

    item.onclick = () => {
      document.getElementById("newHostname").value = sw.bridge;
      document.getElementById("newIP").value = sw.ip;

      if (sw.bridge.includes("core")) {
        document.getElementById("newRole").value = "core";
      } else if (sw.bridge.includes("dist")) {
        document.getElementById("newRole").value = "distribution";
      } else {
        document.getElementById("newRole").value = "access";
      }

      logActivity(`➡️ Auto-filled form with ${sw.bridge} (${sw.ip})`);
    };

    scanResultsDiv.appendChild(item);
  });

  logActivity(`✅ Scan complete: ${data.results.length} switches detected`);
});

// ===============================
// Add / Update Switch
// ===============================
document.getElementById("addSwitchForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const hostname = document.getElementById("newHostname").value;
  const ip = document.getElementById("newIP").value;
  const role = document.getElementById("newRole").value;

const data = await fetchJSON("/api/switch/", { 
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ hostname, ip, role })
  });

  if (data.ok) {
    logActivity(`✅ Switch saved: ${hostname} (${ip}, ${role})`);
    loadTopology();
  } else {
    logActivity(`❌ Failed to save switch: ${data.error}`);
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

  const username = prompt("Enter SSH username:");
  const password = prompt("Enter SSH password:");

  if (!username || !password) {
    logActivity("⚠️ Backup cancelled (missing credentials)");
    return;
  }

  logActivity(`💾 Starting backup for ${ip}...`);

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
    logActivity(`✅ Backup complete: ${data.meta.bytes} bytes saved`);
  } else {
    logActivity(`❌ Backup failed: ${data.error}`);
  }
});

// ===============================
// Refresh / Topology Visualization
// ===============================
async function loadTopology() {
const data = await fetchJSON("/api/switch/");
  const container = document.getElementById("network-topology");

  const nodes = data.map(sw => ({
    id: sw.ip,
    label: sw.hostname,
    shape: "dot",
    size: 25,
    color:
      sw.role === "core"
        ? "#ff6666"
        : sw.role === "distribution"
        ? "#66b3ff"
        : "#99ff99"
  }));

  const edges = [];
  // simple chain topology (core -> dist -> access)
  const core = nodes.find(n => n.label.includes("core"));
  const dists = nodes.filter(n => n.label.includes("dist"));
  const access = nodes.filter(n => n.label.includes("access"));

  dists.forEach(d => edges.push({ from: core.id, to: d.id }));
  access.forEach((a, i) => edges.push({ from: dists[i % dists.length].id, to: a.id }));

  const network = new vis.Network(container, { nodes, edges }, {
    physics: { enabled: true },
    edges: { arrows: { to: { enabled: false } } }
  });

  network.on("click", (params) => {
    if (params.nodes.length > 0) {
      const ip = params.nodes[0];
      showSwitchDetails(ip);
    }
  });
}

async function showSwitchDetails(ip) {
const sw = await fetchJSON(`/api/switch/${ip}`);
  document.getElementById("switchName").textContent = sw.hostname || ip;
  document.getElementById("switchIP").textContent = sw.ip || "—";
  document.getElementById("switchRole").textContent = sw.role || "—";

  const statusDiv = document.getElementById("switchStatus");
  statusDiv.querySelector("span").textContent = sw.status || "unknown";

  logActivity(`📋 Viewing details for ${sw.hostname} (${ip})`);
}

// ===============================
// Init
// ===============================
document.getElementById("refreshBtn").addEventListener("click", loadTopology);
window.onload = loadTopology;
