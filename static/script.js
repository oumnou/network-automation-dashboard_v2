// Fixed Network Scanner for Cisco Devices
// Main dashboard functionality with proper error handling

// Global state
let networkGraph = null;
let currentDevices = [];
let selectedDevice = null;
let scanInProgress = false;

// Initialize the dashboard when page loads
document.addEventListener('DOMContentLoaded', () => {
    console.log('🚀 Initializing Cisco Network Dashboard...');
    initializeDashboard();
});

function initializeDashboard() {
    try {
        initializeNetworkTopology();
        initializeScanner();
        initializeEventListeners();
        initializeKeyboardShortcuts();
        loadInitialData();
        logActivity('✅ Dashboard initialized successfully');
    } catch (error) {
        console.error('Dashboard initialization error:', error);
        logActivity(`❌ Dashboard initialization failed: ${error.message}`);
        showErrorNotification('Failed to initialize dashboard');
    }
}

// ===============================
// Network Topology Management
// ===============================

function initializeNetworkTopology() {
    const container = document.getElementById('network-topology');
    if (!container) {
        console.error('Network topology container not found');
        return;
    }

    const options = {
        nodes: {
            shape: 'dot',
            size: 25,
            font: { size: 12, color: '#ffffff' },
            borderWidth: 2
        },
        edges: {
            color: { color: '#475569', highlight: '#60a5fa' },
            width: 2,
            smooth: { type: 'cubicBezier', forceDirection: 'vertical' }
        },
        physics: {
            enabled: true,
            hierarchicalRepulsion: {
                nodeDistance: 150,
                springLength: 200,
                springConstant: 0.01
            }
        },
        interaction: {
            hover: true,
            selectConnectedEdges: false
        },
        layout: {
            hierarchical: {
                enabled: true,
                direction: 'UD',
                sortMethod: 'hubsize',
                nodeSpacing: 150,
                levelSeparation: 200
            }
        }
    };

    networkGraph = new vis.Network(container, { nodes: [], edges: [] }, options);
    
    // Add click event listener
    networkGraph.on('click', handleNodeClick);
    networkGraph.on('hoverNode', handleNodeHover);
}

function updateNetworkTopology(devices) {
    if (!networkGraph || !devices || devices.length === 0) {
        console.warn('Cannot update topology: missing network graph or devices');
        return;
    }

    const nodes = [];
    const edges = [];

    devices.forEach(device => {
        if (device.authenticated) {
            const nodeColor = getRoleColor(device.role_hint);
            const nodeIcon = getCiscoDeviceIcon(device);
            
            nodes.push({
                id: device.ip,
                label: `${nodeIcon} ${device.hostname || device.ip}\n${device.role_hint}`,
                color: {
                    background: nodeColor,
                    border: device.authenticated ? '#34d399' : '#ef4444',
                    highlight: { background: nodeColor, border: '#60a5fa' }
                },
                size: device.role_hint === 'core' ? 35 : device.role_hint === 'distribution' ? 30 : 25,
                level: device.role_hint === 'core' ? 0 : device.role_hint === 'distribution' ? 1 : 2,
                deviceData: device
            });

            // Create logical connections based on network hierarchy
            if (device.role_hint === 'distribution' && devices.some(d => d.role_hint === 'core' && d.authenticated)) {
                const coreDevice = devices.find(d => d.role_hint === 'core' && d.authenticated);
                if (coreDevice) {
                    edges.push({
                        from: coreDevice.ip,
                        to: device.ip,
                        label: 'Trunk'
                    });
                }
            } else if (device.role_hint === 'access') {
                // Connect access switches to distribution switches
                const distDevices = devices.filter(d => d.role_hint === 'distribution' && d.authenticated);
                if (distDevices.length > 0) {
                    // Simple round-robin connection
                    const distDevice = distDevices[nodes.length % distDevices.length];
                    edges.push({
                        from: distDevice.ip,
                        to: device.ip,
                        label: 'Access'
                    });
                }
            }
        }
    });

    try {
        networkGraph.setData({ nodes, edges });
        networkGraph.fit();
        logActivity(`🌐 Topology updated: ${nodes.length} devices, ${edges.length} connections`);
        updateTopologyStatus(devices);
    } catch (error) {
        console.error('Error updating topology:', error);
        logActivity(`❌ Topology update failed: ${error.message}`);
    }
}

function handleNodeClick(params) {
    if (params.nodes.length > 0) {
        const nodeId = params.nodes[0];
        const device = currentDevices.find(d => d.ip === nodeId);
        if (device) {
            selectDevice(device);
            logActivity(`👆 Selected device: ${device.hostname || device.ip}`);
        }
    }
}

function handleNodeHover(params) {
    // Optional: Add hover effects or tooltips
}

// ===============================
// Enhanced Scanner
// ===============================

function initializeScanner() {
    const scanTypeSelector = document.getElementById('scanTypeSelector');
    const networkRange = document.getElementById('networkRange');
    const scanBtn = document.getElementById('scanNetworkBtn');

    if (scanTypeSelector) {
        scanTypeSelector.addEventListener('change', handleScanTypeChange);
        // Set default to quick scan
        scanTypeSelector.value = 'known_cisco';
        handleScanTypeChange({ target: scanTypeSelector });
    }

    if (scanBtn) {
        scanBtn.addEventListener('click', handleNetworkScan);
    }

    // IP validation for single device mode
    if (networkRange) {
        networkRange.addEventListener('input', validateIPInput);
    }
}

function handleScanTypeChange(e) {
    const scanType = e.target.value;
    const networkRange = document.getElementById('networkRange');
    const scanBtn = document.getElementById('scanNetworkBtn');
    const scanHelp = document.getElementById('scanTypeHelp');
    const rangeLabel = document.getElementById('rangeLabel');

    if (!networkRange || !scanBtn) return;

    switch(scanType) {
        case 'known_cisco':
            networkRange.value = '10.10.20.0/24';
            networkRange.disabled = true;
            scanBtn.textContent = '⚡ Quick Scan Cisco Devices';
            if (scanHelp) scanHelp.textContent = 'Recommended: Scans your 7 known Cisco devices (fastest)';
            if (rangeLabel) rangeLabel.textContent = 'Network Range (Auto-set)';
            break;
            
        case 'full':
            networkRange.disabled = false;
            networkRange.value = '10.10.20.0/24';
            networkRange.placeholder = 'Enter network range (e.g., 192.168.1.0/24)';
            scanBtn.textContent = '🔍 Scan Full Network';
            if (scanHelp) scanHelp.textContent = 'Scans entire network range - may take longer';
            if (rangeLabel) rangeLabel.textContent = 'Network Range';
            break;
            
        case 'single':
            networkRange.disabled = false;
            networkRange.value = '';
            networkRange.placeholder = 'Enter single IP (e.g., 10.10.20.3)';
            scanBtn.textContent = '🎯 Scan Single Device';
            if (scanHelp) scanHelp.textContent = 'Test connectivity to a specific device';
            if (rangeLabel) rangeLabel.textContent = 'Device IP Address';
            break;
    }
    
    logActivity(`[SCAN] Mode changed to: ${scanType}`);
}

async function handleNetworkScan() {
    if (scanInProgress) {
        logActivity('⚠️ Scan already in progress - please wait');
        return;
    }

    const scanType = document.getElementById('scanTypeSelector')?.value || 'known_cisco';
    const range = document.getElementById('networkRange')?.value?.trim() || '';
    const scanBtn = document.getElementById('scanNetworkBtn');
    
    if (!scanBtn) return;

    // Validate input for single device scan
    if (scanType === 'single' && !isValidIP(range)) {
        showErrorNotification('Please enter a valid IP address');
        return;
    }

    scanInProgress = true;
    updateScanProgress(0, 'Initializing scan...');
    logActivity(`🔍 Starting ${scanType} scan...`);
    
    scanBtn.disabled = true;
    scanBtn.textContent = "⏳ Scanning...";

    try {
        let data;
        
        switch(scanType) {
            case 'known_cisco':
                updateScanProgress(25, 'Scanning known Cisco devices...');
                data = await fetchJSON("/api/scan/known", { method: "POST" });
                break;
                
            case 'single':
                updateScanProgress(25, `Testing device ${range}...`);
                data = await fetchJSON("/api/scan/single", { 
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ ip: range })
                });
                break;
                
            case 'full':
            default:
                updateScanProgress(25, `Scanning network ${range}...`);
                data = await fetchJSON("/api/scan/", { 
                    method: "POST",
                    headers: { "Content-Type": "application/json" },
                    body: JSON.stringify({ 
                        network: range,
                        scan_type: "full"
                    })
                });
                break;
        }

        updateScanProgress(75, 'Processing results...');
        await new Promise(resolve => setTimeout(resolve, 500)); // Brief pause for UI
        
        displayScanResults(data);
        updateScanProgress(100, 'Scan complete!');
        
        setTimeout(() => {
            hideScanProgress();
        }, 1500);
        
    } catch (error) {
        console.error("Scan error:", error);
        logActivity(`❌ Scan failed: ${error.message}`);
        showErrorNotification(`Scan failed: ${error.message}`);
        hideScanProgress();
    } finally {
        scanInProgress = false;
        scanBtn.disabled = false;
        scanBtn.textContent = getScanButtonText(scanType);
    }
}

function getScanButtonText(scanType) {
    switch(scanType) {
        case 'known_cisco': return '⚡ Quick Scan Cisco Devices';
        case 'single': return '🎯 Scan Single Device';
        case 'full': return '🔍 Scan Full Network';
        default: return '🔍 Scan Network';
    }
}

function updateScanProgress(percent, text) {
    const progressDiv = document.getElementById('scanProgress');
    const progressFill = document.getElementById('progressFill');
    const progressText = document.getElementById('progressText');
    
    if (progressDiv && progressFill && progressText) {
        progressDiv.style.display = 'block';
        progressFill.style.width = `${percent}%`;
        progressText.textContent = text;
        
        if (percent > 0 && percent < 100) {
            progressDiv.classList.add('scanning');
        } else {
            progressDiv.classList.remove('scanning');
        }
    }
}

function hideScanProgress() {
    const progressDiv = document.getElementById('scanProgress');
    if (progressDiv) {
        progressDiv.style.display = 'none';
        progressDiv.classList.remove('scanning');
    }
}

// ===============================
// Results Display
// ===============================

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
        scanResultsDiv.innerHTML = createNoResultsMessage();
        logActivity("⚠️ No devices detected");
        return;
    }

    // Store current devices globally
    currentDevices = data.results;

    // Add scan summary
    const summary = createScanSummary(data);
    scanResultsDiv.appendChild(summary);

    // Add device results
    data.results.forEach((device, index) => {
        const item = createDeviceResultItem(device, index);
        scanResultsDiv.appendChild(item);
    });

    // Add topology validation if available
    if (data.validation) {
        const validation = createTopologyValidation(data.validation);
        scanResultsDiv.appendChild(validation);
    }

    // Update topology and stats
    updateNetworkTopology(data.results);
    updateNetworkStats(data.results);

    const deviceCount = data.results.length;
    const authCount = data.results.filter(d => d.authenticated).length;
    logActivity(`✅ Scan complete: ${authCount}/${deviceCount} devices accessible`);
}

function createNoResultsMessage() {
    return `
        <div style="text-align: center; padding: 20px; color: #9ca3af;">
            <div style="font-size: 24px; margin-bottom: 10px;">🔍</div>
            <div>No devices found</div>
            <div style="font-size: 12px; margin-top: 8px;">
                Try Quick Scan for known Cisco devices or check network connectivity
            </div>
        </div>
    `;
}

function createScanSummary(data) {
    const summary = document.createElement("div");
    summary.className = "scan-summary";
    
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
            ${data.scan_info ? 
                `Duration: ${data.scan_info.duration}s | Type: ${data.scan_info.scan_type} | Range: ${data.scan_info.network_range || 'known devices'}` : 
                'Scan completed'
            }
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
                <button class="btn btn-sm btn-success" onclick="selectDevice(${JSON.stringify(device).replace(/"/g, '&quot;')})">
                    👁️ Select
                </button>
                ${device.authenticated ? `
                <button class="btn btn-sm" onclick="testConnectivity('${device.ip}')" style="background: #8b5cf6; color: white;">
                    🔗 Test
                </button>
                <button class="btn btn-sm btn-success" onclick="backupDevice('${device.ip}')">
                    💾 Backup
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

// ===============================
// Device Management
// ===============================

function selectDevice(device) {
    selectedDevice = device;
    updateDeviceDetails(device);
    
    // Highlight in topology
    if (networkGraph) {
        networkGraph.selectNodes([device.ip]);
    }
}

function updateDeviceDetails(device) {
    const elements = {
        switchName: device.hostname || device.ip,
        switchRole: device.role_hint || 'Unknown',
        switchIP: device.ip,
        switchModel: device.model || 'Unknown',
        switchIOS: device.ios_version || 'Unknown',
        interfacesValue: device.interface_count || 0,
        uptimeValue: formatUptime(device.uptime),
        portsValue: device.open_ports?.length || 0,
        priorityValue: device.priority || 'N/A'
    };

    Object.entries(elements).forEach(([id, value]) => {
        const element = document.getElementById(id);
        if (element) {
            element.textContent = value;
        }
    });

    // Update status indicator
    const statusElement = document.getElementById('switchStatus');
    if (statusElement) {
        const statusClass = device.authenticated ? 'status-healthy' : 'status-critical';
        const statusText = device.authenticated ? 'Online' : 'Offline';
        statusElement.className = `status-indicator ${statusClass}`;
        statusElement.querySelector('span').textContent = statusText;
    }
}

// ===============================
// Event Listeners & Utilities
// ===============================

function initializeEventListeners() {
    // Quick scan button
    const quickScanBtn = document.getElementById('quickScanBtn');
    if (quickScanBtn) {
        quickScanBtn.addEventListener('click', () => {
            const scanTypeSelector = document.getElementById('scanTypeSelector');
            if (scanTypeSelector) {
                scanTypeSelector.value = 'known_cisco';
                handleScanTypeChange({ target: scanTypeSelector });
                handleNetworkScan();
            }
        });
    }

    // Validate topology button
    const validateBtn = document.getElementById('validateBtn');
    if (validateBtn) {
        validateBtn.addEventListener('click', validateTopology);
    }

    // Refresh button
    const refreshBtn = document.getElementById('refreshBtn');
    if (refreshBtn) {
        refreshBtn.addEventListener('click', () => {
            if (currentDevices.length > 0) {
                updateNetworkTopology(currentDevices);
                logActivity('🔄 Topology refreshed');
            }
        });
    }

    // Device action buttons
    const backupBtn = document.getElementById('backupBtn');
    if (backupBtn) {
        backupBtn.addEventListener('click', () => {
            if (selectedDevice) {
                backupDevice(selectedDevice.ip);
            }
        });
    }

    const testConnBtn = document.getElementById('testConnBtn');
    if (testConnBtn) {
        testConnBtn.addEventListener('click', () => {
            if (selectedDevice) {
                testConnectivity(selectedDevice.ip);
            }
        });
    }

    // Clear log button
    const clearLogBtn = document.getElementById('clearLogBtn');
    if (clearLogBtn) {
        clearLogBtn.addEventListener('click', clearActivityLog);
    }
}

function initializeKeyboardShortcuts() {
    document.addEventListener('keydown', (e) => {
        if (e.ctrlKey || e.metaKey) {
            switch(e.key) {
                case 'q':
                    e.preventDefault();
                    document.getElementById('quickScanBtn')?.click();
                    break;
                case 't':
                    e.preventDefault();
                    document.getElementById('validateBtn')?.click();
                    break;
                case 'r':
                    e.preventDefault();
                    document.getElementById('refreshBtn')?.click();
                    break;
            }
        }
    });
}

async function loadInitialData() {
    try {
        // Try to load any existing device data or perform initial scan
        logActivity('🔍 Performing initial quick scan...');
        
        // Small delay to let UI settle
        setTimeout(() => {
            const quickScanBtn = document.getElementById('quickScanBtn');
            if (quickScanBtn) {
                quickScanBtn.click();
            }
        }, 1000);
    } catch (error) {
        console.error('Error loading initial data:', error);
        logActivity(`⚠️ Initial scan failed: ${error.message}`);
    }
}

async function validateTopology() {
    logActivity('🔍 Validating network topology...');
    
    try {
        const data = await fetchJSON('/api/scan/topology/validate');
        
        if (data.validation) {
            displayTopologyValidation(data.validation);
            logActivity(`✅ Topology validation complete: ${data.validation.topology_valid ? 'Valid' : 'Issues detected'}`);
        }
    } catch (error) {
        console.error('Topology validation error:', error);
        logActivity(`❌ Topology validation failed: ${error.message}`);
        showErrorNotification('Topology validation failed');
    }
}

async function testConnectivity(ip) {
    logActivity(`🔗 Testing connectivity to ${ip}...`);
    
    try {
        const data = await fetchJSON(`/api/scan/test-connectivity/${ip}`, {
            method: "POST"
        });
        
        if (data.connectivity && data.connectivity.authenticated) {
            logActivity(`✅ ${ip}: Connected successfully`);
            showSuccessNotification(`${ip} is accessible`);
        } else {
            logActivity(`❌ ${ip}: Connection failed - ${data.connectivity?.error || 'Unknown error'}`);
            showErrorNotification(`${ip} connection failed`);
        }
    } catch (error) {
        console.error("Connectivity test error:", error);
        logActivity(`❌ ${ip}: Test failed - ${error.message}`);
        showErrorNotification(`Test failed: ${error.message}`);
    }
}

async function backupDevice(ip) {
    logActivity(`💾 Starting backup for ${ip}...`);
    
    try {
        const data = await fetchJSON('/api/backup/', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ ip: ip })
        });
        
        if (data.success) {
            logActivity(`✅ Backup completed for ${ip}`);
            showSuccessNotification(`Configuration backed up successfully`);
        } else {
            logActivity(`❌ Backup failed for ${ip}: ${data.error || 'Unknown error'}`);
            showErrorNotification(`Backup failed: ${data.error || 'Unknown error'}`);
        }
    } catch (error) {
        console.error("Backup error:", error);
        logActivity(`❌ Backup failed for ${ip}: ${error.message}`);
        showErrorNotification(`Backup failed: ${error.message}`);
    }
}

// ===============================
// UI Status Updates
// ===============================

function updateTopologyStatus(devices) {
    const statusDiv = document.getElementById('topologyStatus');
    if (!statusDiv) return;

    const authenticated = devices.filter(d => d.authenticated);
    const total = devices.length;
    const expectedTotal = 7; // Your known Cisco devices

    let statusClass, statusIcon, statusTitle, statusDetails;

    if (authenticated.length === expectedTotal) {
        statusClass = '';
        statusIcon = '✅';
        statusTitle = 'Topology Healthy';
        statusDetails = 'All expected devices accessible';
    } else if (authenticated.length >= Math.floor(expectedTotal * 0.7)) {
        statusClass = 'warning';
        statusIcon = '⚠️';
        statusTitle = 'Topology Warning';
        statusDetails = `${expectedTotal - authenticated.length} devices unreachable`;
    } else {
        statusClass = 'critical';
        statusIcon = '❌';
        statusTitle = 'Topology Critical';
        statusDetails = `Only ${authenticated.length}/${expectedTotal} devices accessible`;
    }

    statusDiv.className = `topology-status ${statusClass}`;
    statusDiv.style.display = 'block';
    
    statusDiv.innerHTML = `
        <div class="status-content">
            <div class="status-icon">${statusIcon}</div>
            <div class="status-text">
                <div class="status-title">${statusTitle}</div>
                <div class="status-details">${statusDetails}</div>
            </div>
            <div class="status-stats">${authenticated.length}/${expectedTotal}</div>
        </div>
    `;
}

function updateNetworkStats(devices) {
    const total = devices.length;
    const online = devices.filter(d => d.authenticated).length;
    const offline = total - online;

    const elements = {
        totalDevices: total,
        onlineDevices: online,
        offlineDevices: offline,
        lastScanTime: new Date().toLocaleTimeString()
    };

    Object.entries(elements).forEach(([id, value]) => {
        const element = document.getElementById(id);
        if (element) {
            element.textContent = value;
        }
    });

    // Update health status
    const healthStatus = document.getElementById('healthStatus');
    const healthScore = document.getElementById('healthScore');
    
    if (healthStatus && healthScore) {
        const healthPercentage = total > 0 ? Math.round((online / total) * 100) : 0;
        let healthClass, healthText;

        if (healthPercentage >= 90) {
            healthClass = 'healthy';
            healthText = 'Excellent';
        } else if (healthPercentage >= 70) {
            healthClass = 'warning';
            healthText = 'Good';
        } else if (healthPercentage >= 50) {
            healthClass = 'warning';
            healthText = 'Fair';
        } else {
            healthClass = 'critical';
            healthText = 'Poor';
        }

        healthStatus.className = `health-status ${healthClass}`;
        healthStatus.querySelector('span').textContent = healthText;
        healthScore.textContent = `${healthPercentage}%`;
    }
}

function displayTopologyValidation(validation) {
    const validationDiv = createTopologyValidation(validation);
    
    // Find scan results area or create temporary display
    const scanResults = document.getElementById('scanResults');
    if (scanResults) {
        scanResults.style.display = 'block';
        scanResults.appendChild(validationDiv);
    } else {
        // Show as notification if no scan results area
        const message = validation.topology_valid ? 
            `✅ Topology Valid: ${validation.found_count}/${validation.expected_count} devices` :
            `⚠️ Topology Issues: Missing ${validation.missing_devices?.length || 0} devices`;
        
        if (validation.topology_valid) {
            showSuccessNotification(message);
        } else {
            showWarningNotification(message);
        }
    }
}

// ===============================
// Notification System
// ===============================

function showSuccessNotification(message) {
    showNotification(message, 'success');
}

function showErrorNotification(message) {
    showNotification(message, 'error');
}

function showWarningNotification(message) {
    showNotification(message, 'warning');
}

function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    
    const colors = {
        success: '#10b981',
        error: '#ef4444',
        warning: '#f59e0b',
        info: '#3b82f6'
    };

    const icons = {
        success: '✅',
        error: '❌',
        warning: '⚠️',
        info: 'ℹ️'
    };

    notification.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background: ${colors[type]};
        color: white;
        padding: 12px 16px;
        border-radius: 8px;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
        z-index: 1000;
        font-size: 14px;
        max-width: 300px;
        opacity: 0;
        transition: all 0.3s ease;
        transform: translateX(100px);
    `;
    
    notification.innerHTML = `
        <div style="display: flex; align-items: center; gap: 8px;">
            <span style="font-size: 16px;">${icons[type]}</span>
            <div>${message}</div>
        </div>
    `;
    
    document.body.appendChild(notification);
    
    // Animate in
    setTimeout(() => {
        notification.style.opacity = '1';
        notification.style.transform = 'translateX(0)';
    }, 10);
    
    // Remove after delay
    setTimeout(() => {
        notification.style.opacity = '0';
        notification.style.transform = 'translateX(100px)';
        setTimeout(() => {
            if (notification.parentNode) {
                notification.remove();
            }
        }, 300);
    }, 4000);
}

// ===============================
// Utility Functions
// ===============================

function getCiscoDeviceIcon(device) {
    if (!device.role_hint) return '🔌';
    
    switch (device.role_hint.toLowerCase()) {
        case 'core': return '🏛️';
        case 'distribution': return '🏢';
        case 'access': return '🏠';
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

function isValidIP(ip) {
    const ipRegex = /^(\d{1,3}\.){3}\d{1,3}$/;
    if (!ipRegex.test(ip)) return false;
    
    const parts = ip.split('.');
    return parts.every(part => {
        const num = parseInt(part, 10);
        return num >= 0 && num <= 255;
    });
}

function validateIPInput(event) {
    const input = event.target;
    const validation = document.getElementById('ipValidation');
    
    if (!validation) return;
    
    if (input.value.trim() === '') {
        validation.textContent = '';
        validation.className = 'ip-validation';
        return;
    }
    
    if (isValidIP(input.value.trim())) {
        validation.textContent = '✅ Valid IP address';
        validation.className = 'ip-validation valid';
    } else {
        validation.textContent = '❌ Invalid IP address format';
        validation.className = 'ip-validation invalid';
    }
}

function formatUptime(uptime) {
    if (!uptime || uptime === 'unknown') return 'Unknown';
    
    // If uptime is already formatted (contains 'days', 'hours', etc.), return as-is
    if (typeof uptime === 'string' && (uptime.includes('day') || uptime.includes('hour') || uptime.includes('minute'))) {
        return uptime;
    }
    
    // If it's a number (seconds), format it
    if (typeof uptime === 'number') {
        const days = Math.floor(uptime / (24 * 3600));
        const hours = Math.floor((uptime % (24 * 3600)) / 3600);
        const minutes = Math.floor((uptime % 3600) / 60);
        
        if (days > 0) {
            return `${days}d ${hours}h`;
        } else if (hours > 0) {
            return `${hours}h ${minutes}m`;
        } else {
            return `${minutes}m`;
        }
    }
    
    return uptime;
}

async function fetchJSON(url, options = {}) {
    try {
        const response = await fetch(url, options);
        
        if (!response.ok) {
            let errorMessage = `HTTP ${response.status}: ${response.statusText}`;
            
            try {
                const errorData = await response.json();
                if (errorData.error) {
                    errorMessage = errorData.error;
                }
            } catch (e) {
                // If we can't parse the error response as JSON, use the status text
            }
            
            throw new Error(errorMessage);
        }
        
        return await response.json();
    } catch (error) {
        if (error.name === 'TypeError' && error.message.includes('fetch')) {
            throw new Error('Network error: Unable to connect to server. Please check if the server is running.');
        }
        throw error;
    }
}

function logActivity(message) {
    console.log(message);
    
    const activityLog = document.getElementById('activityLog');
    if (activityLog) {
        const logEntry = document.createElement('div');
        logEntry.className = 'log-entry';
        logEntry.textContent = `[${new Date().toLocaleTimeString()}] ${message}`;
        
        activityLog.appendChild(logEntry);
        activityLog.scrollTop = activityLog.scrollHeight;
        
        // Limit log entries to prevent memory issues
        const entries = activityLog.querySelectorAll('.log-entry');
        if (entries.length > 100) {
            entries[0].remove();
        }
    }
}

function clearActivityLog() {
    const activityLog = document.getElementById('activityLog');
    if (activityLog) {
        activityLog.innerHTML = '';
        logActivity('📋 Activity log cleared');
    }
}

// Make functions globally available for HTML onclick handlers
window.selectDevice = selectDevice;
window.testConnectivity = testConnectivity;
window.backupDevice = backupDevice;

// Add CSS for animations if not already present
if (!document.getElementById('dashboard-animations')) {
    const style = document.createElement('style');
    style.id = 'dashboard-animations';
    style.textContent = `
        @keyframes slideIn {
            from {
                opacity: 0;
                transform: translateY(10px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        @keyframes pulse {
            0%, 100% { opacity: 1; }
            50% { opacity: 0.6; }
        }
        
        .scanning .progress-fill {
            animation: pulse 1.5s ease-in-out infinite;
        }
        
        .scan-summary {
            background: linear-gradient(135deg, rgba(34, 197, 94, 0.1) 0%, rgba(16, 185, 129, 0.1) 100%);
            border: 1px solid rgba(34, 197, 94, 0.3);
            border-radius: 8px;
            padding: 12px;
            margin-bottom: 16px;
            font-size: 13px;
            animation: slideIn 0.4s ease forwards;
        }
        
        .btn {
            border: none;
            border-radius: 4px;
            padding: 4px 8px;
            font-size: 12px;
            cursor: pointer;
            transition: all 0.2s ease;
            text-decoration: none;
            display: inline-block;
            text-align: center;
        }
        
        .btn:hover {
            transform: translateY(-1px);
        }
        
        .btn:disabled {
            opacity: 0.6;
            cursor: not-allowed;
            transform: none;
        }
        
        .btn-sm {
            padding: 2px 6px;
            font-size: 11px;
        }
        
        .btn-success {
            background-color: #10b981;
            color: white;
        }
        
        .btn-success:hover {
            background-color: #059669;
        }
        
        .btn-secondary {
            background-color: #6b7280;
            color: white;
        }
        
        .btn-secondary:hover {
            background-color: #4b5563;
        }
        
        .progress-bar {
            width: 100%;
            height: 6px;
            background: rgba(71, 85, 105, 0.3);
            border-radius: 3px;
            overflow: hidden;
            margin-bottom: 8px;
        }
        
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #3b82f6, #60a5fa);
            width: 0%;
            transition: width 0.3s ease;
            border-radius: 3px;
        }
        
        .progress-text {
            font-size: 12px;
            color: #94a3b8;
            text-align: center;
        }
        
        #scanProgress {
            margin: 12px 0;
        }
        
        .ip-validation {
            font-size: 11px;
            margin-top: 2px;
        }
        
        .ip-validation.valid {
            color: #10b981;
        }
        
        .ip-validation.invalid {
            color: #ef4444;
        }
    `;
    document.head.appendChild(style);
}