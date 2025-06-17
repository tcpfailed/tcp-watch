const express = require('express');
const app = express();
const http = require('http').createServer(app);
const WebSocket = require('ws');
const fs = require('fs');
const os = require('os');

const wss = new WebSocket.Server({ server: http });

let prevCPU = null;
let prevNet = null;
let prevTime = Date.now();

function getSystemData() {
    try {
        const cpuInfo = fs.readFileSync('/proc/stat', 'utf8').split('\n')[0];
        const cpuParts = cpuInfo.split(/\s+/).slice(1).map(num => parseInt(num));
        
        let cpuUsage = 0;
        if (prevCPU) {
            const prevTotal = prevCPU.reduce((acc, val) => acc + val, 0);
            const currentTotal = cpuParts.reduce((acc, val) => acc + val, 0);
            const prevIdle = prevCPU[3] + prevCPU[4];
            const currentIdle = cpuParts[3] + cpuParts[4];
            
            cpuUsage = ((1 - (currentIdle - prevIdle) / (currentTotal - prevTotal)) * 100).toFixed(2);
        }
        prevCPU = cpuParts;

        const netInfo = fs.readFileSync('/proc/net/dev', 'utf8');
        const eth0Line = netInfo.split('\n').find(line => line.includes('eth0'));
        const netParts = eth0Line.trim().split(/\s+/);
        const currentBytes = parseInt(netParts[1]);
        const currentPackets = parseInt(netParts[2]);
        
        let packetsPerSec = 0;
        let currentMbit = 0;
        
        if (prevNet) {
            const timeDiff = (Date.now() - prevTime) / 1000;
            packetsPerSec = Math.floor((currentPackets - prevNet.packets) / timeDiff);
            currentMbit = ((currentBytes - prevNet.bytes) * 8 / 1000000) / timeDiff;
        }
        
        prevNet = { bytes: currentBytes, packets: currentPackets };
        prevTime = Date.now();

        const memInfo = fs.readFileSync('/proc/meminfo', 'utf8');
        const memTotal = parseInt(memInfo.match(/MemTotal:\s+(\d+)/)[1]) / 1024;
        const memFree = parseInt(memInfo.match(/MemAvailable:\s+(\d+)/)[1]) / 1024;
        const memUsed = memTotal - memFree;

        let blockedIPs = {};
        if (fs.existsSync('blacklistedips.log')) {
            const blacklist = fs.readFileSync('blacklistedips.log', 'utf8');
            blacklist.split('\n').forEach(line => {
                if (line.trim()) {
                    const match = line.match(/IP: ([\d.]+)/);
                    if (match) {
                        blockedIPs[match[1]] = {
                            timestamp: new Date().toISOString(),
                            attackType: line.includes('Attack Type:') ? 
                                line.split('Attack Type:')[1].split('|')[0].trim() : 'Unknown'
                        };
                    }
                }
            });
        }

        return {
            cpuUsage,
            ramUsed: Math.round(memUsed),
            ramTotal: Math.round(memTotal),
            ramFree: Math.round(memFree),
            packetsPerSec,
            currentMbit: currentMbit.toFixed(2),
            blockedIPs,
            incomingIPs: Object.keys(blockedIPs).length
        };
    } catch (error) {
        console.error('Error getting system data:', error);
        return {};
    }
}

app.get('/', (req, res) => {
    res.send(`
<!DOCTYPE html>
<html>
<head>
    <title>TCP Watch Web</title>
    <style>
        body {
            background-color: #1a1a1a;
            color: #ffffff;
            font-family: 'Courier New', monospace;
            margin: 0;
            padding: 20px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        .header {
            background-color: #2d2d2d;
            padding: 15px;
            border-radius: 5px;
            margin-bottom: 20px;
            border: 1px solid #3d3d3d;
        }
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(2, 1fr);
            gap: 20px;
            margin-bottom: 20px;
        }
        .stats-box {
            background-color: #2d2d2d;
            padding: 15px;
            border-radius: 5px;
            border: 1px solid #3d3d3d;
        }
        .graph-container {
            background-color: #2d2d2d;
            padding: 15px;
            border-radius: 5px;
            height: 300px;
            margin-bottom: 20px;
            border: 1px solid #3d3d3d;
        }
        .value {
            color: #00ff00;
        }
        #trafficGraph {
            width: 100%;
            height: 100%;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>TCP Watch Web v1.0.1</h1>
        </div>
        
        <div class="stats-grid">
            <div class="stats-box">
                <h2>System Stats</h2>
                <p>CPU Usage: <span class="value" id="cpuUsage">0%</span></p>
                <p>RAM Usage: <span class="value" id="ramUsage">0/0 MB</span></p>
                <p>Free RAM: <span class="value" id="ramFree">0 MB</span></p>
            </div>
            
            <div class="stats-box">
                <h2>Network Stats</h2>
                <p>Current PPS: <span class="value" id="currentPPS">0</span></p>
                <p>Current MBit/s: <span class="value" id="currentMbit">0</span></p>
                <p>Blocked IPs: <span class="value" id="blockedIPs">0</span></p>
            </div>
        </div>

        <div class="graph-container">
            <canvas id="trafficGraph"></canvas>
        </div>

        <div class="stats-box">
            <h2>Blocked IPs</h2>
            <div id="ipList"></div>
        </div>
    </div>

    <script>
        class Graph {
            constructor(canvas) {
                this.canvas = canvas;
                this.ctx = canvas.getContext('2d');
                this.values = new Array(100).fill(0);
                this.maxValue = 1;
                this.resize();
                window.addEventListener('resize', () => this.resize());
            }

            resize() {
                this.canvas.width = this.canvas.parentElement.offsetWidth - 30;
                this.canvas.height = this.canvas.parentElement.offsetHeight - 30;
            }

            addValue(value) {
                this.values.push(value);
                this.values.shift();
                this.maxValue = Math.max(...this.values) * 1.2;
                this.draw();
            }

            draw() {
                const ctx = this.ctx;
                const width = this.canvas.width;
                const height = this.canvas.height;

                ctx.fillStyle = '#1a1a1a';
                ctx.fillRect(0, 0, width, height);

                ctx.strokeStyle = '#333';
                ctx.lineWidth = 1;

                for(let i = 0; i < width; i += 50) {
                    ctx.beginPath();
                    ctx.moveTo(i, 0);
                    ctx.lineTo(i, height);
                    ctx.stroke();
                }
                
                for(let i = 0; i < height; i += 50) {
                    ctx.beginPath();
                    ctx.moveTo(0, i);
                    ctx.lineTo(width, i);
                    ctx.stroke();
                }

                ctx.strokeStyle = '#00ff00';
                ctx.lineWidth = 2;
                ctx.beginPath();

                const step = width / (this.values.length - 1);
                this.values.forEach((value, i) => {
                    const x = i * step;
                    const y = height - (value / this.maxValue * height);
                    
                    if(i === 0) {
                        ctx.moveTo(x, y);
                    } else {
                        ctx.lineTo(x, y);
                    }
                });

                ctx.stroke();
            }
        }

        const graph = new Graph(document.getElementById('trafficGraph'));
        const ws = new WebSocket(\`ws://\${window.location.host}\`);
        
        ws.onmessage = function(event) {
            const data = JSON.parse(event.data);
            
            document.getElementById('cpuUsage').textContent = \`\${data.cpuUsage}%\`;
            document.getElementById('ramUsage').textContent = 
                \`\${data.ramUsed}/\${data.ramTotal} MB\`;
            document.getElementById('ramFree').textContent = \`\${data.ramFree} MB\`;
            document.getElementById('currentPPS').textContent = data.packetsPerSec;
            document.getElementById('currentMbit').textContent = \`\${data.currentMbit} MBit/s\`;
            document.getElementById('blockedIPs').textContent = data.incomingIPs;

            graph.addValue(parseFloat(data.currentMbit));

            const ipList = document.getElementById('ipList');
            ipList.innerHTML = '';
            for (const [ip, details] of Object.entries(data.blockedIPs)) {
                ipList.innerHTML += \`
                    <div style="margin: 10px 0; padding: 10px; background: #3d3d3d;">
                        <p>IP: \${ip}</p>
                        <p>Attack Type: \${details.attackType}</p>
                        <p>Time: \${new Date(details.timestamp).toLocaleString()}</p>
                    </div>
                \`;
            }
        };

        ws.onclose = function() {
            console.log('Connection closed');
            setTimeout(() => location.reload(), 1000);
        };
    </script>
</body>
</html>
    `);
});

wss.on('connection', (ws) => {
    console.log('Client connected');
    
    const interval = setInterval(() => {
        const data = getSystemData();
        ws.send(JSON.stringify(data));
    }, 1000);

    ws.on('close', () => {
        clearInterval(interval);
        console.log('Client disconnected');
    });
});

const PORT = 1234;
http.listen(PORT, () => {
    console.log(`TCP Watch Web Version running on http://localhost:${PORT}`);
});
