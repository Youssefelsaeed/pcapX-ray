# PCAP Intrusion Detection Tool 🚨

A Python-based command-line tool for detecting suspicious activity in `.pcap` files, simulating real-world threat analysis techniques.

---

## 📦 Features

- ✅ Detects **Port Scans**, **DNS Tunneling**, **Brute-force Attempts**, and **Data Exfiltration**
- 📊 Optional visual timeline of events
- ⚙️ Configurable detection thresholds via `.env` or CLI
- 📄 Output in CSV or JSON
- 🔎 Supports PCAP filtering and fast analysis using `--max-packets`

---

## 🛠️ Installation

1. Clone the repo or download the files.
2. Create a virtual environment (recommended):
    ```bash
    python -m venv venv
    venv\Scripts\activate  # on Windows
    source venv/bin/activate  # on macOS/Linux
    ```
3. Install dependencies:
    ```bash
    pip install -r requirements.txt
    ```

4. Create a `.env` file like this:
    ```
    PORT_SCAN_THRESHOLD=10
    BRUTE_FORCE_THRESHOLD=5
    DNS_QUERY_LENGTH_THRESHOLD=50
    DATA_EXFIL_THRESHOLD_MB=10
    ```

---

## 🚀 Usage

```bash
python analyzer.py path/to/file.pcap --output report.json --format json --plot --max-packets 5000
```

### 🔧 CLI Options

| Option              | Description                                      |
|---------------------|--------------------------------------------------|
| `--format`          | Output format: `csv` or `json`                   |
| `--plot`            | Generate timeline image                          |
| `--syn-threshold`   | Override port scan SYN threshold                 |
| `--no-dns`          | Disable DNS tunneling detection                  |
| `--no-brute`        | Disable brute-force detection                    |
| `--no-exfil`        | Disable data exfiltration detection              |
| `--max-packets`     | Limit how many packets to process (for speed)    |

---

## 📊 Output

- `report.csv` or `report.json`: detection results
- `report.png`: timeline chart (optional)

---

## 📁 Example PCAP Sources

- [https://www.malware-traffic-analysis.net](https://www.malware-traffic-analysis.net)  
  (Password for ZIPs: `malware-traffic-analysis.net`)

---

## 🤝 License

MIT License
