# Zero-Trust Network Map (ZTNM)

> A real-time network visualization and zero-trust security analysis tool that discovers devices on your local network, maps connections, and evaluates your network's security posture against zero-trust principles.

![ZTNM Screenshot](https://img.shields.io/badge/status-active-brightgreen) ![Python](https://img.shields.io/badge/python-3.9+-blue) ![React](https://img.shields.io/badge/react-18.x-61DAFB) ![FastAPI](https://img.shields.io/badge/FastAPI-0.104+-009688)

---

## Features

### 🔍 Network Discovery
- **ARP-based device discovery** — scans your local network to find all connected devices
- **Port scanning** — detects open TCP ports on discovered devices (30+ common ports)
- **Service fingerprinting** — identifies running services via banner grabbing
- **OS detection** — guesses operating systems via TTL analysis and port patterns
- **Vendor identification** — identifies hardware vendors from MAC address prefixes

### 🛡️ Zero-Trust Analysis
Automated evaluation against core zero-trust principles:

| Principle | What ZTNM Checks |
|-----------|------------------|
| **Never trust, always verify** | Trust levels assigned per device based on risk |
| **Assume breach** | Blast radius analysis for every device |
| **Least privilege** | Suspicious cross-device connections flagged |
| **Micro-segmentation** | Network segmentation gaps identified |
| **Continuous monitoring** | Monitoring coverage gaps reported |

- **Compliance scoring** — overall 0–100 zero-trust compliance score
- **Risk assessment** — per-device risk scores based on open ports, service types, and device class
- **Blast radius analysis** — what would happen if each device were compromised
- **Actionable recommendations** — prioritized remediation steps

### 🎨 3D Network Visualization
- Interactive **3D force-directed graph** using Three.js / React Three Fiber
- Color-coded nodes by **trust level** (green → yellow → orange → red)
- Connection lines with **risk-based coloring**
- Click any device to see **detailed info and services**
- Real-time updates during scanning via **WebSocket**

### 📊 Dashboard
- Device detail panel with open ports, services, OS, and vendor
- Trust distribution overview
- Scan history
- Progress tracking during active scans

---

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    ZTNM Architecture                         │
├──────────────────────┬──────────────────────────────────────┤
│   Frontend (React)   │     Backend (FastAPI + Python)       │
│                      │                                      │
│  ┌────────────────┐  │  ┌──────────────────────────────┐   │
│  │  Network Graph  │  │  │  REST API  (FastAPI)         │   │
│  │  (Three.js)     │◄─┼──┤  WebSocket (/ws)             │   │
│  └────────────────┘  │  │  Static File Serving          │   │
│  ┌────────────────┐  │  └──────────────────────────────┘   │
│  │  Device Panel   │  │  ┌──────────────────────────────┐   │
│  └────────────────┘  │  │  Network Scanner               │   │
│  ┌────────────────┐  │  │  • ARP discovery               │   │
│  │  Trust Overlay  │  │  │  • TCP port scanning          │   │
│  └────────────────┘  │  │  • OS & service fingerprinting │   │
│  ┌────────────────┐  │  └──────────────────────────────┘   │
│  │  Scan Controls  │  │  ┌──────────────────────────────┐   │
│  └────────────────┘  │  │  Zero-Trust Analyzer           │   │
│                      │  │  • Compliance scoring          │   │
│  Port: 3000 (dev)    │  │  • Risk assessment             │   │
│  Proxied to backend  │  │  • Blast radius analysis       │   │
│                      │  │  • Recommendations engine      │   │
│                      │  │  └──────────────────────────────┘   │
│                      │  Port: 8000                          │
└──────────────────────┴──────────────────────────────────────┘
```

### Tech Stack

**Backend**
- **Python 3.9+** with **FastAPI** for REST/WebSocket API
- **Uvicorn** as the ASGI server
- Native Python socket programming for network scanning (no external nmap required)

**Frontend**
- **React 18** with **Vite** for build tooling
- **@react-three/fiber** & **@react-three/drei** for 3D network graph
- **Three.js** for WebGL rendering

---

## Getting Started

### Prerequisites

- **Python 3.9+**
- **Node.js 18+** and **npm** (or pnpm/yarn)
- A local network with other devices (for meaningful scanning)

### Installation

#### 1. Clone & Backend Setup

```bash
git clone https://github.com/08theabhi/Zero-trust_network_map.git
cd Zero-trust_network_map

# Create a virtual environment (recommended)
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install Python dependencies
cd backend
pip install -r requirements.txt
```

#### 2. Frontend Setup

```bash
cd ../frontend
npm install

# Build for production
npm run build
```

#### 3. Run the Application

Start the backend server (from the `backend` directory):

```bash
python main.py
```

The server will start on `http://localhost:8000`. It serves:
- The React frontend at `http://localhost:8000/`
- The REST API at `http://localhost:8000/api/`
- WebSocket at `ws://localhost:8000/ws`

#### Development Mode

To run the frontend with hot reload during development:

```bash
cd frontend
npm run dev
```

This starts the Vite dev server on `http://localhost:3000`, which proxies API requests to the backend at `http://localhost:8000`.

---

## API Reference

### REST Endpoints

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/health` | Health check |
| `POST` | `/api/scan` | Start a new network scan |
| `GET` | `/api/scan/{scan_id}` | Get results for a specific scan |
| `GET` | `/api/scans` | List recent scans |
| `GET` | `/api/network-info` | Get detected local network info |

### WebSocket (`/ws`)

Real-time updates during scanning:

```json
// Progress update
{ "type": "scan_progress", "scan_id": "...", "status": "scanning", "percent": 45, "message": "Scanning 192.168.1.5..." }

// Scan complete
{ "type": "scan_complete", "scan_id": "...", "result": { ... } }
```

---

## Project Structure

```
Zero-trust_network_map/
├── backend/
│   ├── main.py                # FastAPI server, WebSocket, REST endpoints
│   ├── models.py              # Data models (Device, Service, ScanResult, etc.)
│   ├── scanner.py             # Network discovery, port scanning, OS detection
│   ├── trust_analyzer.py      # Zero-trust compliance analysis engine
│   └── requirements.txt       # Python dependencies
├── frontend/
│   ├── src/
│   │   ├── components/
│   │   │   ├── DevicePanel.jsx       # Device details sidebar
│   │   │   ├── NetworkGraph.jsx      # 3D force-directed graph
│   │   │   ├── ScanControls.jsx      # Scan trigger and status
│   │   │   └── TrustOverlay.jsx      # Zero-trust compliance report
│   │   ├── hooks/
│   │   │   └── useWebSocket.js       # WebSocket connection hook
│   │   ├── App.jsx                   # Main application layout
│   │   └── App.css                   # Styling
│   ├── index.html
│   ├── package.json
│   └── vite.config.js
└── README.md
```

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `HOST` | `0.0.0.0` | Backend server bind address |
| `PORT` | `8000` | Backend server port |
| `SCAN_TIMEOUT` | `60` | Max scan duration in seconds |
| `MAX_SCAN_HOSTS` | `50` | Max hosts to scan per network |

### Scan Customization

Edit `scanner.py` to customize:
- **Port list** — modify `COMMON_PORTS` array
- **Service risk scores** — update `SERVICE_RISK_MAP`
- **Vendor prefixes** — extend the `vendors` dictionary in `get_mac_vendor()`

---

## Security Considerations

> ⚠️ **IMPORTANT**: This tool performs active network scanning. Use responsibly.

- Run only on **networks you own** or have explicit permission to scan
- Port scanning may trigger **IDS/IPS alerts** on monitored networks
- The tool uses **non-intrusive TCP connect scans** (no SYN flood, no stealth techniques)
- No data is stored persistently (in-memory storage only, max 100 scan results)
- The backend does **not** require root/admin privileges for basic scanning

---

## License

This project is open source and available under the [MIT License](LICENSE).

---

## Acknowledgments

Built as a demonstration of zero-trust security principles combined with interactive network visualization.
