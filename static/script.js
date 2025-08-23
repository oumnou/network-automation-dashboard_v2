// Enhanced Network Scanner for Cisco Devices - Fixed Version
// Replace the existing scanning logic in script.js

// ===============================
// Enhanced Network Scanner for Cisco
// ===============================

// Initialize the enhanced scanner when page loads
document.addEventListener('DOMContentLoaded', () => {
  initializeScanner();
});

function initializeScanner() {
  // Create scan type selector if it doesn't exist
  if (!document.getElementById('scanTypeSelector')) {
    createScanTypeSelector();
  }
  
  // Set up scan button event listener
  const scanBtn = document.getElementById("scanNetworkBtn");
  if (scanBtn) {
    // Remove existing listeners to prevent duplicates
    scanBtn.replaceWith(scanBtn.cloneNode(true));
    const newScanBtn = document.getElementById("scanNetworkBtn");
    newScanBtn.addEventListener("click", handleNetworkScan);
  }
  
  // Set default to quick scan for known Cisco devices
  setTimeout(() => {
    const selector = document.getElementById('scanTypeSelector');
    if (selector) {
      selector.value = 'known_cisco';
      selector.dispatchEvent(new Event('change'));
    }
  }, 100);
}

async function handleNetworkScan() {
  const range = document.getElementById("networkRange").value.trim();
  const scanType = getScanType(range);
  const scanBtn = document.getElementById("scanNetworkBtn");
  
  if (!scanBtn) return;
  
  logActivity(`🔍 Starting ${scanType} scan...`);
  scanBtn.disabled = true;
  scanBtn.textContent = "⏳ Scanning...";

  try {
    let data;
    
    if (scanType === "known_cisco") {
      // Quick scan of known Cisco IPs only
      data = await fetchJSON("/api/scan/known", { method: "POST" });
      logActivity(`⚡ Quick scanning known Cisco devices`);
    } else if (scanType === "single_device") {
      // Single device scan
      data = await fetchJSON("/api/scan/single", { 
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ip: range })
      });
      logActivity(`🎯 Scanning single device: ${range}`);
    } else {
      // Full network scan with the specified range
      data = await fetchJSON("/api/scan/", { 
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ 
          network: range,
          scan_type: scanType === "known_cisco" ? "known_only" : "full"
        })
      });
      logActivity(`🔍 Full network scan of ${range}`);
    }

    displayScanResults(data);
    
  } catch (error) {
    console.error("Scan error:", error);
    logActivity(`❌ Scan failed: ${error.message}`);
    showErrorNotification(`Scan failed: ${error.message}`);
  } finally {
    scanBtn.disabled = false;
    scanBtn.textContent = "🔍 Scan Network";
  }
}

// Determine scan type based on input
function getScanType(range) {
  if (!range || range === "10.10.20.0/24" || range === "") {
    return "known_cisco"; // Default to known devices for efficiency
  }
  
  // Check if user entered a specific known IP
  const knownIPs = ["10.10.20.3", "10.10.20.4", "10.10.20.5", "10.10.20.10", "10.10.20.11", "10.10.20.12", "10.10.20.13"];
  if (knownIPs.includes(range)) {
    return "single_device";
  }
  
  // Check if it's a single IP address
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(range)) {
    return "single_device";
  }
  
  return "full"; // User wants to scan a custom range
}

// Add scan type selector to the UI
function createScanTypeSelector() {
  const scanBtn = document.getElementById('scanNetworkBtn');
  if (!scanBtn) {
    console.error("Scan button not found");
    return;
  }
  
  const scanCard = scanBtn.closest('.card-content');
  if (!scanCard) {
    console.error("Scan card not found");
    return;
  }
  
  // Create scan type selector
  const scanTypeDiv = document.createElement('div');
  scanTypeDiv.className = 'form-group';
  scanTypeDiv.innerHTML = `
    <label class="form-label">Scan Type</label>
    <select class="form-select" id="scanTypeSelector">
      <option value="known_cisco">Quick Scan (Known Cisco IPs)</option>
      <option value="full">Full Network Scan</option>
      <option value="single">Single Device</option>
    </select>
    <div style="font-size: 11px; color: #9ca3af; margin-top: 4px;">
      Quick scan is recommended for your Cisco devices
    </div>
  `;
  
  // Insert before the scan button
  scanCard.insertBefore(scanTypeDiv, scanBtn);
  
  // Update scan behavior based on selection
  document.getElementById('scanTypeSelector').addEventListener('change', handleScanTypeChange);
}

function handleScanTypeChange(e) {
  const scanType = e.target.value;
  const networkRange = document.getElementById('networkRange');
  const scanBtn = document.getElementById('scanNetworkBtn');
  
  if (!networkRange || !scanBtn) return;
  
  switch(scanType) {
    case 'known_cisco':
      networkRange.value = '10.10.20.0/24';
      networkRange.disabled = true;
      scanBtn.textContent = '⚡ Quick Scan Cisco Devices';
      logActivity('[INFO] Quick scan mode: Will scan known Cisco IPs only');
      break;
      
    case 'full':
      networkRange.disabled = false;
      networkRange.placeholder = 'Enter network range (e.g., 192.168.1.0/24)';
      scanBtn.textContent = '🔍 Scan Full Network';
      logActivity('[INFO] Full scan mode: Will scan entire network range');
      break;
      
    case 'single':
      networkRange.disabled = false;
      networkRange.value = '';
      networkRange.placeholder = 'Enter single IP (e.g., 10.10.20.3)';
      scanBtn.textContent = '🎯 Scan Single Device';
      logActivity('[INFO] Single device mode: Enter one IP address');
      break;
  }
}

// Enhanced scan results display
function displayScanResults(data) {
  const scanResultsDiv = document.getElementById("scanResults");
  if (!scanResultsDiv) {
    console.error("Scan results div not found");
    return;
  }
  
  scanResultsDiv.innerHTML = "";
  scanResultsDiv.style.display = "block";

  // Handle single device results
  if (data.result && !data.results) {
    data.results = [data.result];
  }

  if (!data.results || data.results.length === 0) {
    scanResultsDiv.innerHTML = `
      <div style="text-align: center; padding: 20px; color: #9ca3af;">
        <div style="font-size: 24px; margin-bottom: 10px;">🔍</div>
        <div>No devices found</div>
        <div style="font-size: 12px; margin-top: 8px;">
          Try Quick Scan for known Cisco devices or check network connectivity
        </div>
      </div>
    `;
    logActivity("⚠️ No devices detected - check network connectivity");
    return;
  }

  // Add scan summary with enhanced info
  if (data.scan_info || data.results.length > 0) {
    const summary = createScanSummary(data);
    scanResultsDiv.appendChild(summary);
  }

  // Enhanced device display
  data.results.forEach((device, index) => {
    const item = createDeviceResultItem(device, index);
    scanResultsDiv.appendChild(item);
  });

  // Add topology validation if available
  if (data.validation) {
    const validation = createTopologyValidation(data.validation);
    scanResultsDiv.appendChild(validation);
  }

  const deviceCount = data.results.length;
  const authCount = data.results.filter(d => d.authenticated).length;
  logActivity(`✅ Scan complete: ${authCount}/${deviceCount} devices accessible`);
}

function createScanSummary(data) {
  const summary = document.createElement("div");
  summary.className = "scan-summary";
  summary.style.cssText = `
    background: linear-gradient(135deg, rgba(34, 197, 94, 0.1) 0%, rgba(16, 185, 129, 0.1) 100%); 
    border: 1px solid rgba(34, 197, 94, 0.3); 
    border-radius: 8px; 
    padding: 12px; 
    margin-bottom: 16px; 
    font-size: 13px;
  `;
  
  const totalFound = data.results.length;
  const authenticatedCount = data.results.filter(d => d.authenticated).length;
  const successRate = totalFound > 0 ? Math.round((authenticatedCount / totalFound) * 100) : 0;
  
  summary.innerHTML = `
    <div style="display: flex; justify-content: space-between; align-items: center;">
      <div>
        <strong>📊 Scan Results:</strong> ${authenticatedCount}/${totalFound} devices accessible
      </div>
      <div style="color: #10b981; font-weight: 600;">
        ${successRate}% success rate
      </div>
    </div>
    <div style="margin-top: 6px; font-size: 12px; color: #6b7280;">
      ${data.scan_info ? `Duration: ${data.scan_info.duration}s | Type: ${data.scan_info.scan_type} | Range: ${data.scan_info.network_range || 'known devices'}` : 'Scan completed'}
    </div>
  `;
  
  return summary;
}

function createDeviceResultItem(device, index) {
  const item = document.createElement("div");
  item.className = "scan-result-item";
  
  const deviceIcon = getCiscoDeviceIcon(device);
  const roleColor = getRoleColor(device.role_hint);
  const statusIcon = device.authenticated ? "✅" : "❌";
  const statusText = device.authenticated ? "Accessible" : "Failed";
  const statusColor = device.authenticated ? "#10b981" : "#ef4444";
  
  // Safely encode device data for onclick
  const deviceDataEncoded = encodeURIComponent(JSON.stringify(device));
  
  item.innerHTML = `
    <div style="display: flex; justify-content: space-between; align-items: center;">
      <div style="flex: 1;">
        <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 8px;">
          <span style="font-size: 18px;">${deviceIcon}</span>
          <strong style="color: ${roleColor}; font-size: 14px;">${device.hostname || device.ip}</strong>
          <span style="color: ${statusColor}; font-size: 12px; font-weight: 600;">${statusText}</span>
        </div>
        
        <div style="color: #9ca3af; font-size: 12px; line-height: 1.5;">
          <div style="display: grid; grid-template-columns: repeat(2, 1fr); gap: 4px;">
            <div><strong>IP:</strong> ${device.ip}</div>
            <div><strong>Role:</strong> ${device.role_hint || 'Unknown'}</div>
            <div><strong>Model:</strong> ${device.model || 'Unknown'}</div>
            <div><strong>IOS:</strong> ${device.ios_version || 'Unknown'}</div>
          </div>
          <div style="margin-top: 4px; font-size: 11px;">
            <strong>Interfaces:</strong> ${device.interface_count || 0} | 
            <strong>Uptime:</strong> ${device.uptime || 'Unknown'} |
            <strong>Ports:</strong> ${device.open_ports?.join(', ') || 'N/A'}
          </div>
        </div>
      </div>
      
      <div style="display: flex; flex-direction: column; gap: 6px; margin-left: 12px;">
        <button class="btn btn-sm btn-success" onclick="addCiscoDevice('${device.ip}', decodeURIComponent('${deviceDataEncoded}'))">
          ➕ Add
        </button>
        <button class="btn btn-sm btn-secondary" onclick="viewDeviceDetails('${device.ip}')">
          👁️ Details
        </button>
        ${device.authenticated ? `
        <button class="btn btn-sm" onclick="testConnectivity('${device.ip}')" style="background: #8b5cf6; color: white;">
          🔗 Test
        </button>
        ` : ''}
      </div>
    </div>
  `;
  
  // Enhanced styling with animation
  item.style.cssText = `
    padding: 16px; 
    margin: 8px 0; 
    background: rgba(31, 41, 59, 0.8); 
    border-radius: 10px; 
    border: 1px solid rgba(71, 85, 105, 0.5); 
    transition: all 0.3s ease;
    opacity: 0;
    transform: translateY(10px);
    animation: slideIn 0.3s ease forwards;
    animation-delay: ${index * 0.1}s;
  `;

  item.addEventListener('mouseenter', () => {
    item.style.backgroundColor = "rgba(71, 85, 105, 0.3)";
    item.style.borderColor = roleColor;
    item.style.transform = "translateY(-2px)";
    item.style.boxShadow = `0 4px 12px rgba(0, 0, 0, 0.2)`;
  });
  
  item.addEventListener('mouseleave', () => {
    item.style.backgroundColor = "rgba(31, 41, 59, 0.8)";
    item.style.borderColor = "rgba(71, 85, 105, 0.5)";
    item.style.transform = "translateY(0)";
    item.style.boxShadow = "none";
  });

  return item;
}

function createTopologyValidation(validation) {
  const validationDiv = document.createElement("div");
  validationDiv.style.cssText = `
    background: ${validation.topology_valid ? 
      'linear-gradient(135deg, rgba(34, 197, 94, 0.1) 0%, rgba(16, 185, 129, 0.1) 100%)' : 
      'linear-gradient(135deg, rgba(239, 68, 68, 0.1) 0%, rgba(220, 38, 38, 0.1) 100%)'
    };
    border: 1px solid ${validation.topology_valid ? 'rgba(34, 197, 94, 0.3)' : 'rgba(239, 68, 68, 0.3)'};
    border-radius: 8px;
    padding: 12px;
    margin-top: 16px;
    font-size: 13px;
  `;
  
  const icon = validation.topology_valid ? "✅" : "⚠️";
  const status = validation.topology_valid ? "Valid" : "Issues Detected";
  
  let content = `
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 8px;">
      <strong>${icon} Topology ${status}</strong>
      <span>${validation.found_count}/${validation.expected_count} expected devices</span>
    </div>
  `;
  
  if (validation.missing_devices && validation.missing_devices.length > 0) {
    content += `
      <div style="color: #ef4444; font-size: 12px; margin-bottom: 4px;">
        <strong>Missing:</strong> ${validation.missing_devices.join(', ')}
      </div>
    `;
  }
  
  if (validation.role_distribution) {
    const roles = validation.role_distribution;
    content += `
      <div style="font-size: 12px; color: #6b7280;">
        <strong>Distribution:</strong> ${roles.core || 0} core, ${roles.distribution || 0} distribution, ${roles.access || 0} access
      </div>
    `;
  }
  
  validationDiv.innerHTML = content;
  return validationDiv;
}

// Add test connectivity function
async function testConnectivity(ip) {
  logActivity(`🔗 Testing connectivity to ${ip}...`);
  
  try {
    const data = await fetchJSON(`/api/scan/single`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ ip })
    });
    
    const result = data.result || data;
    
    if (result && result.authenticated) {
      logActivity(`✅ ${ip}: Connected successfully - ${result.hostname || ip}`);
      showConnectionTestResult(ip, result, true);
    } else {
      logActivity(`❌ ${ip}: Connection failed - ${result?.error || 'Unknown error'}`);
      showConnectionTestResult(ip, result, false);
    }
  } catch (error) {
    console.error("Connectivity test error:", error);
    logActivity(`❌ ${ip}: Test failed - ${error.message}`);
    showConnectionTestResult(ip, null, false, error.message);
  }
}

function showConnectionTestResult(ip, result, success, errorMessage = null) {
  // Create a temporary notification
  const notification = document.createElement('div');
  notification.style.cssText = `
    position: fixed;
    top: 20px;
    right: 20px;
    background: ${success ? '#10b981' : '#ef4444'};
    color: white;
    padding: 12px 16px;
    border-radius: 8px;
    box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
    z-index: 1000;
    font-size: 14px;
    max-width: 300px;
    opacity: 0;
    transition: opacity 0.3s ease;
  `;
  
  notification.innerHTML = `
    <div style="font-weight: 600;">${success ? '✅' : '❌'} ${ip}</div>
    <div style="font-size: 12px; margin-top: 4px;">
      ${success ? 
        `${result?.hostname || ip} ${result?.model ? `(${result.model})` : ''}` : 
        (errorMessage || result?.error || 'Connection failed')
      }
    </div>
  `;
  
  document.body.appendChild(notification);
  
  // Animate in
  setTimeout(() => {
    notification.style.opacity = '1';
  }, 10);
  
  // Remove after 3 seconds
  setTimeout(() => {
    notification.style.opacity = '0';
    setTimeout(() => {
      if (notification.parentNode) {
        notification.remove();
      }
    }, 300);
  }, 3000);
}

function showErrorNotification(message) {
  showConnectionTestResult('Error', { error: message }, false);
}

// Helper functions (these might need to be implemented based on your existing code)
function getCiscoDeviceIcon(device) {
  if (!device.role_hint) return '🔌';
  
  switch (device.role_hint.toLowerCase()) {
    case 'core': return '🏢';
    case 'distribution': return '🌐';
    case 'access': return '💻';
    case 'switch': return '🔀';
    case 'router': return '📡';
    default: return '🔌';
  }
}

function getRoleColor(role) {
  if (!role) return '#9ca3af';
  
  switch (role.toLowerCase()) {
    case 'core': return '#dc2626';
    case 'distribution': return '#ea580c';
    case 'access': return '#16a34a';
    case 'switch': return '#2563eb';
    case 'router': return '#7c3aed';
    default: return '#9ca3af';
  }
}

// Stub functions - these should be implemented based on your existing application
function logActivity(message) {
  console.log(message);
  // Add to activity log if element exists
  const activityLog = document.getElementById('activityLog');
  if (activityLog) {
    const logEntry = document.createElement('div');
    logEntry.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
    activityLog.appendChild(logEntry);
    activityLog.scrollTop = activityLog.scrollHeight;
  }
}

async function fetchJSON(url, options = {}) {
  const response = await fetch(url, options);
  if (!response.ok) {
    throw new Error(`HTTP error! status: ${response.status}`);
  }
  return await response.json();
}

function addCiscoDevice(ip, deviceDataString) {
  try {
    const deviceData = typeof deviceDataString === 'string' ? 
      JSON.parse(decodeURIComponent(deviceDataString)) : deviceDataString;
    console.log('Adding device:', deviceData);
    logActivity(`➕ Adding device ${ip} to configuration`);
    // Implement your device addition logic here
  } catch (error) {
    console.error('Error adding device:', error);
    logActivity(`❌ Failed to add device ${ip}: ${error.message}`);
  }
}

function viewDeviceDetails(ip) {
  console.log('Viewing details for:', ip);
  logActivity(`👁️ Viewing details for ${ip}`);
  // Implement your device details view logic here
}

// Add CSS for animations
if (!document.getElementById('scanner-animations')) {
  const style = document.createElement('style');
  style.id = 'scanner-animations';
  style.textContent = `
    @keyframes slideIn {
      to {
        opacity: 1;
        transform: translateY(0);
      }
    }
    
    .scan-summary {
      animation: slideIn 0.4s ease forwards;
    }
    
    .btn {
      border: none;
      border-radius: 4px;
      padding: 4px 8px;
      font-size: 12px;
      cursor: pointer;
      transition: all 0.2s ease;
    }
    
    .btn:hover {
      transform: translateY(-1px);
    }
    
    .btn-sm {
      padding: 2px 6px;
      font-size: 11px;
    }
    
    .btn-success {
      background-color: #10b981;
      color: white;
    }
    
    .btn-secondary {
      background-color: #6b7280;
      color: white;
    }
    
    .form-group {
      margin-bottom: 12px;
    }
    
    .form-label {
      display: block;
      margin-bottom: 4px;
      font-size: 13px;
      font-weight: 600;
      color: #374151;
    }
    
    .form-select {
      width: 100%;
      padding: 8px 12px;
      border: 1px solid #d1d5db;
      border-radius: 6px;
      background-color: white;
      font-size: 14px;
    }
  `;
  document.head.appendChild(style);
}