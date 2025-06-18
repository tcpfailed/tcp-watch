const express = require('express');
const app = express();
const http = require('http').createServer(app);
const WebSocket = require('ws');
const os = require('os');
const fs = require('fs').promises;
const path = require('path');

const PORT = 1234;

const wss = new WebSocket.Server({ server: http });

function getLocalIP() {
  const interfaces = os.networkInterfaces();
  for (const name in interfaces) {
    for (const iface of interfaces[name]) {
      if (iface.family === 'IPv4' && !iface.internal) {
        return iface.address;
      }
    }
  }
  return 'localhost';
}

let prevNet = null;
let prevTime = Date.now();

async function readNet() {
  const net = await fs.readFile('/proc/net/dev', 'utf8');
  const lines = net.split('\n').slice(2);

  let rxBytes = 0;
  let rxPackets = 0;
  let txBytes = 0;
  let txPackets = 0;

  for (const line of lines) {
    if (!line.trim()) continue;
    const [iface, rest] = line.split(':');
    if (iface.trim() === 'lo') continue; 
    const data = rest.trim().split(/\s+/);

    rxBytes += parseInt(data[0]);
    rxPackets += parseInt(data[1]);
    txBytes += parseInt(data[8]);
    txPackets += parseInt(data[9]);
  }

  return { rxBytes, rxPackets, txBytes, txPackets };
}

async function readCPU() {
  const stat = await fs.readFile('/proc/stat', 'utf8');
  const line = stat.split('\n')[0];
  return line.trim().split(/\s+/).slice(1).map(Number);
}

let prevCPU = null;
async function getCPUUsage() {
  const cpuCurrent = await readCPU();
  if (!prevCPU) {
    prevCPU = cpuCurrent;
    return 0;
  }
  const totalDiff = cpuCurrent.reduce((a, b, i) => a + b - prevCPU[i], 0);
  const idleDiff = cpuCurrent[3] - prevCPU[3];
  prevCPU = cpuCurrent;
  return ((1 - idleDiff / totalDiff) * 100).toFixed(2);
}

async function readMem() {
  const mem = await fs.readFile('/proc/meminfo', 'utf8');
  const total = mem.match(/^MemTotal:\s+(\d+)/m);
  const avail = mem.match(/^MemAvailable:\s+(\d+)/m);
  const totalMB = Math.round(parseInt(total[1]) / 1024);
  const availMB = Math.round(parseInt(avail[1]) / 1024);
  return { totalMB, availMB, usedMB: totalMB - availMB };
}

async function readBlockedIPs() {
  try {
    const filePath = path.resolve('blacklistedips.log');
    const exists = await fs.stat(filePath).then(() => true).catch(() => false);
    if (!exists) return {};
    const data = await fs.readFile(filePath, 'utf8');
    const ips = {};
    data.split('\n').forEach(line => {
      if (!line.trim()) return;

      
      const timeMatch = line.match(/^\[(.*?)\]/);
      
      const timestamp = timeMatch
  ? new Date(`20${timeMatch[1].replace(/-/g, '/').replace(' ', 'T')}`).toISOString()
  : new Date().toISOString();

      
      const ipMatch = line.match(/IP: ([\d.]+)/);
      if (!ipMatch) return;
      const ip = ipMatch[1];

      
      const reasonMatch = line.match(/Reason:\s*(.*?)(?:\d+\s*packets\/sec)?$/);
      const attackType = reasonMatch ? reasonMatch[1].trim() : 'Unknown';

      ips[ip] = { attackType, timestamp };
    });
    return ips;
  } catch {
    return {};
  }
}

async function getSystemData() {
  const cpuUsage = await getCPUUsage();

  const now = Date.now();
  const netStats = await readNet();

  let packetsPerSec = 0;
  let currentMbit = 0;

  if (prevNet && netStats) {
    const timeDiff = (now - prevTime) / 1000;

    packetsPerSec = Math.floor((netStats.rxPackets + netStats.txPackets - (prevNet.rxPackets + prevNet.txPackets)) / timeDiff);
    currentMbit = ((netStats.rxBytes + netStats.txBytes - (prevNet.rxBytes + prevNet.txBytes)) * 8 / 1_000_000) / timeDiff;
  }

  prevNet = netStats;
  prevTime = now;

  const mem = await readMem();
  const blockedIPs = await readBlockedIPs();

  return {
    cpuUsage,
    ramUsed: mem.usedMB,
    ramTotal: mem.totalMB,
    ramFree: mem.availMB,
    packetsPerSec,
    currentMbit: currentMbit.toFixed(2),
    blockedIPs,
    incomingIPs: Object.keys(blockedIPs).length,
  };
}

wss.on('connection', (ws, req) => {
  const clientIP = req.socket.remoteAddress;

  const sendStats = async () => {
    if (ws.readyState === ws.OPEN) {
      try {
        const data = await getSystemData();

        data.clientIP = clientIP;
        data.clientBytes = prevNet ? (prevNet.rxBytes + prevNet.txBytes) : 0;

        ws.send(JSON.stringify(data));
      } catch (err) {
        console.error('Error sending data', err);
      }
    }
  };

  sendStats();
  const interval = setInterval(sendStats, 1000);
  ws.on('close', () => clearInterval(interval));
});


app.use('/blacklistedips.log', express.static(path.resolve('blacklistedips.log')));

app.get('/', (req, res) => {
res.send(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<meta name="viewport" content="width=device-width, initial-scale=1" />
<title>TCP Monitor</title>
<style>
  body {
    background-color: #121212;
    color: white;
    font-family: Arial, sans-serif;
    padding: 20px;
  }
  .card {
    background: #1e1e1e;
    padding: 15px;
    margin-bottom: 20px;
    border-radius: 8px;
  }
  .value {
    color: #4caf50;
    font-weight: bold;
  }
  canvas {
    background: #202020;
    border-radius: 5px;
  }
  button {
    background: #333;
    border: none;
    padding: 8px 12px;
    color: white;
    border-radius: 5px;
    cursor: pointer;
    margin-bottom: 15px;
  }
  #clientIP, .client-ip {
    color: #4caf50;
    user-select: text;
    transition: color 0.3s ease;
  }
</style>
</head>
<body>
  <h1>TCP Monitor</h1>

  <button id="toggleIPBtn">Hide Client IP</button>

  <div class="card">
    <p>CPU: <span class="value" id="cpuUsage">0%</span></p>
    <p>RAM: <span class="value" id="ramUsage">0 / 0 MB</span></p>
    <p>Free RAM: <span class="value" id="ramFree">0 MB</span></p>
    <p>PPS: <span class="value" id="packetsPerSec">0</span></p>
    <p>Mbps: <span class="value" id="currentMbit">0</span></p>
    <p>Blocked IPs: <span class="value" id="blockedIPs">0</span></p>
    <p>Connected Client IP: <span class="value" id="clientIP">N/A</span></p>
    <p>Client Bytes (RX + TX): <span class="value" id="clientBytes">0</span></p>
  </div>

  <canvas id="trafficChart" height="100"></canvas>

  <div class="card" id="ipList">No blocked IPs yet.</div>

  <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
  <script>
    (function() {
      const wsUrl = 'ws://' + location.host;
      let ws;
      let reconnectTimeout = null;
      let showIP = true;

      const ppsData = [];
      const mbpsData = [];
      const labels = [];

      const cpuUsageEl = document.getElementById('cpuUsage');
      const ramUsageEl = document.getElementById('ramUsage');
      const ramFreeEl = document.getElementById('ramFree');
      const ppsEl = document.getElementById('packetsPerSec');
      const mbpsEl = document.getElementById('currentMbit');
      const blockedIPsEl = document.getElementById('blockedIPs');
      const clientIPEl = document.getElementById('clientIP');
      const clientBytesEl = document.getElementById('clientBytes');
      const ipListEl = document.getElementById('ipList');
      const toggleIPBtn = document.getElementById('toggleIPBtn');

      const ctx = document.getElementById('trafficChart').getContext('2d');

      const chart = new Chart(ctx, {
        type: 'line',
        data: {
          labels,
          datasets: [
            {
              label: 'PPS',
              data: ppsData,
              borderColor: 'white',
              backgroundColor: 'white',
              fill: false,
              tension: 0.3,
              pointRadius: 0,
              borderWidth: 2,
              yAxisID: 'pps',
            },
            {
              label: 'Mbps',
              data: mbpsData,
              borderColor: 'limegreen',
              backgroundColor: 'limegreen',
              fill: false,
              tension: 0.3,
              pointRadius: 0,
              borderWidth: 2,
              yAxisID: 'mbps',
            }
          ]
        },
        options: {
          animation: false,
          interaction: {
            mode: 'nearest',
            intersect: false
          },
          scales: {
            pps: {
              type: 'linear',
              position: 'left',
              ticks: { color: 'white' },
              title: { display: true, text: 'Packets Per Second (PPS)', color: 'white' },
              grid: { color: '#444' },
            },
            mbps: {
              type: 'linear',
              position: 'right',
              ticks: { color: 'limegreen' },
              title: { display: true, text: 'Megabits Per Second (Mbps)', color: 'limegreen' },
              grid: { drawOnChartArea: false },
            },
            x: {
              ticks: { color: '#ccc' },
              grid: { color: '#333' },
            }
          },
          plugins: {
            legend: { labels: { color: 'white' } },
            tooltip: {
              callbacks: {
                label: function(context) {
                  if (context.dataset.label === 'Mbps') {
                    const val = context.parsed.y;
                    if (val >= 1000) {
                      return \`\${context.dataset.label}: \${(val / 1000).toFixed(2)} Gbps\`;
                    }
                    return \`\${context.dataset.label}: \${val.toFixed(2)} Mbps\`;
                  }
                  return \`\${context.dataset.label}: \${context.parsed.y}\`;
                }
              }
            }
          }
        }
      });

      toggleIPBtn.addEventListener('click', () => {
        showIP = !showIP;
        toggleIPBtn.textContent = showIP ? 'Hide Client IP' : 'Show Client IP';

        clientIPEl.style.color = showIP ? '#4caf50' : 'transparent';
        clientIPEl.style.userSelect = showIP ? 'text' : 'none';

        document.querySelectorAll('.client-ip').forEach(el => {
          el.style.color = showIP ? '#4caf50' : 'transparent';
          el.style.userSelect = showIP ? 'text' : 'none';
        });
      });

      function updateIPList(ips) {
        if (!ips || Object.keys(ips).length === 0) {
          ipListEl.innerHTML = '<p>No blocked IPs detected.</p>';
          return;
        }
        const html = Object.entries(ips).map(([ip, { attackType, timestamp }]) =>
          \`<p><b class="client-ip">\${ip}</b>: \${attackType} at \${new Date(timestamp).toLocaleString()}</p>\`
        ).join('');
        ipListEl.innerHTML = html;

        if (!showIP) {
          document.querySelectorAll('.client-ip').forEach(el => {
            el.style.color = 'transparent';
            el.style.userSelect = 'none';
          });
        }
      }

      async function fetchBlockedIPs() {
        try {
          const res = await fetch('/blacklistedips.log');
          if (!res.ok) return {};
          const text = await res.text();
          const ips = {};
          text.split('\\n').forEach(line => {
            if (!line.trim()) return;

            const timeMatch = line.match(/^\\[(.*?)\\]/);
            const timestamp = timeMatch ? \`20\${timeMatch[1].replace(/-/g, '/').replace(' ', 'T')}\` : new Date().toISOString();

            const ipMatch = line.match(/IP: ([\\d.]+)/);
            if (!ipMatch) return;
            const ip = ipMatch[1];

            const reasonMatch = line.match(/Reason:\\s*(.*?)(?:\\d+\\s*packets\\/sec)?$/);
            const attackType = reasonMatch ? reasonMatch[1].trim() : 'Unknown';

            ips[ip] = { attackType, timestamp };
          });
          return ips;
        } catch {
          return {};
        }
      }

      function connectWS() {
        ws = new WebSocket(wsUrl);

        ws.onopen = () => {
          console.log('WebSocket connected');
          if (reconnectTimeout) {
            clearTimeout(reconnectTimeout);
            reconnectTimeout = null;
          }
        };

        ws.onmessage = (evt) => {
          const data = JSON.parse(evt.data);

          cpuUsageEl.textContent = data.cpuUsage + '%';
          ramUsageEl.textContent = \`\${data.ramUsed} / \${data.ramTotal} MB\`;
          ramFreeEl.textContent = data.ramFree + ' MB';
          ppsEl.textContent = data.packetsPerSec;
          mbpsEl.textContent = data.currentMbit;
          blockedIPsEl.textContent = Object.keys(data.blockedIPs || {}).length;
          clientIPEl.textContent = data.clientIP || 'N/A';
          clientBytesEl.textContent = data.clientBytes || 0;

          if (!showIP) {
            clientIPEl.style.color = 'transparent';
            clientIPEl.style.userSelect = 'none';
          } else {
            clientIPEl.style.color = '#4caf50';
            clientIPEl.style.userSelect = 'text';
          }

          if (labels.length >= 60) {
            labels.shift();
            ppsData.shift();
            mbpsData.shift();
          }
          labels.push(new Date().toLocaleTimeString());
          ppsData.push(data.packetsPerSec);
          mbpsData.push(parseFloat(data.currentMbit));

          chart.update();
        };

        ws.onerror = (e) => {
          console.error('WebSocket error', e);
        };

        ws.onclose = () => {
          console.log('WebSocket closed, reconnecting in 2 seconds...');
          if (!reconnectTimeout) {
            reconnectTimeout = setTimeout(() => {
              connectWS();
            }, 2000);
          }
        };
      }

      connectWS();

      async function periodicBlockedIPUpdate() {
        const ips = await fetchBlockedIPs();
        updateIPList(ips);
      }
      periodicBlockedIPUpdate();
      setInterval(periodicBlockedIPUpdate, 10000);
    })();
  </script>
</body>
</html>`);
});

app.get('/data', async (req, res) => {
  try {
    const data = await getSystemData();
    const mbps = parseFloat(data.currentMbit);
    const readableMbps = mbps >= 1000
      ? (mbps / 1000).toFixed(2) + ' Gbps'
      : mbps.toFixed(2) + ' Mbps';
    res.send(`${data.packetsPerSec} PPS | ${readableMbps} | ${Object.keys(data.blockedIPs || {}).length} Connections`);
  } catch {
    res.status(500).send('Error retrieving data');
  }
});

http.listen(PORT, () => {
  console.log(`Server running on http://${getLocalIP()}:${PORT}`);
});
