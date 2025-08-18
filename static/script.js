// Basic state
let switches = [];
let selectedNodeId = null;
let network = null;

// DOM helpers
const $ = (id) => document.getElementById(id);
const logPanel = () => $("activityLog");
function log(msg) {
  const el = logPanel();
  const time = new Date().toLocaleTimeString();
  el.innerHTML += `[${time}] ${msg}<br>`;
  el.scrollTop = el.scrollHeight;
}

// Build / refresh vis-network
function renderNetwork() {
  const nodes = switches.map((s, idx) => ({
    id: s.ip,
    label: `${s.hostname}\n${s.ip}`,
    group: s.role || "access"
  }));
  const edges = []; // Simple for now
  const container = $("network-topology");
  const data = { nodes: new vis.DataSet(nodes), edges: new vis.DataSet(edges) };
  const options = {
    autoResize: true,
    height: "480px",
    nodes: {
      shape: "dot",
      size: 18,
      font: { color: "#e5e7eb" }
    },
    groups: {
      core: { color: "#60a5fa" },
      distribution: { color: "#a78bfa" },
      access: { color: "#34d399" }
    },
    physics: { stabilization: true }
  };
  network = new vis.Network(container, data, options);
  network.on("selectNode", (params) => {
    const nodeId = params.nodes[0];
    selectedNodeId = nodeId;
    const sw = switches.find((s) => s.ip === nodeId);
    if (sw) {
      updateSidebar(sw);
    }
  });
}

// Update switch info panel
function updateSidebar(sw) {
  $("switchName").innerText = sw.hostname || "Unknown";
  $("switchRole").innerText = sw.role || "—";
  $("switchIP").innerText = sw.ip || "—";
  const statusSpan = $("switchStatus").querySelector("span");
  statusSpan.innerText = sw.status || "—";
  // Fake health metrics for now (could be polled via API later)
  $("cpuValue").innerText = sw.cpu ?? Math.floor(10 + Math.random()*50);
  $("memoryValue").innerText = sw.memory ?? Math.floor(20 + Math.random()*60);
  $("tempValue").innerText = sw.temperature ?? Math.floor(30 + Math.random()*20);
  $("interfacesValue").innerText = sw.interfaces ?? 24;
}

// Load switches from backend
async function loadSwitches() {
  const res = await fetch("/api/switch/");
  const data = await res.json();
  switches = data;
  renderNetwork();
}

// Add/Update switch handler
$("addSwitchForm").addEventListener("submit", async (e) => {
  e.preventDefault();
  const payload = {
    hostname: $("newHostname").value.trim(),
    ip: $("newIP").value.trim(),
    role: $("newRole").value
  };
  const res = await fetch("/api/switch/", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });
  if (res.ok) {
    log(`Switch saved: ${payload.hostname} (${payload.ip})`);
    await loadSwitches();
    e.target.reset();
  } else {
    const err = await res.json();
    log(`Error saving switch: ${err.error || res.statusText}`);
  }
});

// Scan network (sidebar card)
$("scanNetworkBtn").addEventListener("click", async () => {
  const range = $("networkRange").value.trim();
  log(`Scanning network ${range}...`);
  const res = await fetch("/api/scan/", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ network: range })
  });
  const data = await res.json();
  $("scanResults").style.display = "block";
  $("scanResults").innerHTML = data.results.map(r => `<div>🔌 ${r.ip} (open: ${r.open_ports.join(",")})</div>`).join("");
  log(`Scan finished with engine: ${data.engine}. Found ${data.results.length} hosts with open ports.`);
});

// Main panel buttons
$("scanBtn").addEventListener("click", () => $("scanNetworkBtn").click());
$("refreshBtn").addEventListener("click", () => loadSwitches());
$("exportBtn").addEventListener("click", async () => {
  const blob = new Blob([JSON.stringify(switches, null, 2)], {type: "application/json"});
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "switches.json";
  document.body.appendChild(a);
  a.click();
  a.remove();
  URL.revokeObjectURL(url);
  log("Exported current switches.json");
});

// Backup button
$("backupBtn").addEventListener("click", async () => {
  if (!selectedNodeId) {
    alert("Select a switch node first.");
    return;
  }
  const ip = selectedNodeId;
  const username = prompt("Username for SSH:");
  if (!username) return;
  const password = prompt("Password for SSH:");
  if (!password) return;
  const enable_password = prompt("Enable password (optional):") || undefined;
  log(`Starting backup for ${ip}...`);
  const res = await fetch("/api/backup/run", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ip, username, password, enable_password })
  });
  const data = await res.json();
  if (data.ok) {
    log(`Backup OK for ${ip}. Saved ${data.meta.bytes} bytes.`);
  } else {
    log(`Backup FAILED for ${ip}: ${data.error}`);
  }
});

// Configure button (placeholder)
$("configBtn").addEventListener("click", () => {
  if (!selectedNodeId) return alert("Select a switch node first.");
  alert("Configuration UI coming soon 🚧");
});

// Mark vulnerable demo
$("markVulnBtn").addEventListener("click", () => {
  if (!selectedNodeId) return alert("Select a switch node first.");
  log(`Marked ${selectedNodeId} as vulnerable (demo).`);
});

// Periodically pull server logs (non-blocking)
async function refreshLogs() {
  try {
    const res = await fetch("/api/logs/tail?n=50");
    const data = await res.json();
    const panel = $("activityLog");
    panel.innerHTML = data.lines.map(ln => ln.replaceAll("&", "&amp;").replaceAll("<", "&lt;")).join("<br>");
    panel.scrollTop = panel.scrollHeight;
  } catch (e) {}
}
setInterval(refreshLogs, 5000);

// Init
document.addEventListener("DOMContentLoaded", async () => {
  await loadSwitches();
  log("Dashboard ready.");
  refreshLogs();
});
