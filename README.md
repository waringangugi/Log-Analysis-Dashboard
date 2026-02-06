# Log Analysis Dashboard

A full-stack web application that analyzes web server logs to detect and visualize security threats including brute force attacks, SQL injection attempts, path traversal, and reconnaissance activity.

## 🔗 Live Demo
**[Coming Soon - Will be deployed on Render]**

## Features

### Attack Detection
- **Brute Force Detection**: Identifies repeated failed login attempts from the same IP
- **SQL Injection Detection**: Scans for common SQL injection patterns in URLs
- **Path Traversal Detection**: Flags attempts to access unauthorized files using `../` sequences
- **Scanning/Reconnaissance**: Detects automated scanning for hidden endpoints

### Visualization
- **Interactive Charts**: Pie chart showing attack type distribution and bar chart of top attacking IPs
- **Real-time Analysis**: Instant feedback on uploaded log files
- **Detailed Reports**: Comprehensive breakdown of each detected threat with IP, timestamp, and details

### User Interface
- Clean, responsive web dashboard
- Upload custom log files or analyze sample data
- Visual severity indicators for different attack types


## Quick Start

### Live Demo
Visit the [live demo](#) to analyze logs immediately without installation.

### Local Installation

**Prerequisites:**
- Python 3.8 or higher
- pip package manager

**Steps:**

1. Clone the repository:
```bash
git clone https://github.com/waringangugi/Log-Analysis-Dashboard.git
cd Log-Analysis-Dashboard
```

2. Create and activate virtual environment:
```bash
python -m venv venv

# Windows:
source venv/Scripts/activate

# Mac/Linux:
source venv/bin/activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Run the application:
```bash
python app.py
```

5. Open your browser to `http://127.0.0.1:5000`

## Usage

### Analyze Sample Logs
1. Click "Analyze Sample Logs" to see detection on pre-loaded examples
2. View statistics, charts, and detailed threat breakdown

### Upload Your Own Logs
1. Click "Upload & Analyze Your Logs"
2. Select a `.txt` or `.log` file in Apache/Nginx Common Log Format
3. View real-time analysis results

### Supported Log Format
Standard Apache/Nginx Common Log Format:
```
IP - - [timestamp] "METHOD /path HTTP/1.1" status size
```

Example:
```
192.168.1.100 - - [03/Feb/2026:10:15:30 +0000] "GET /index.html HTTP/1.1" 200 1234
```

## Detection Logic

### Brute Force Attacks
- **Threshold**: 5+ failed login attempts (401/403 status codes)
- **Logic**: Counts failed authentications per IP address

### SQL Injection
- **Patterns Detected**: `' OR '`, `'--`, `UNION SELECT`, `DROP TABLE`, `1=1`
- **Logic**: Regex pattern matching in URL parameters

### Path Traversal
- **Patterns Detected**: `../`, `..\`
- **Logic**: Identifies directory traversal attempts in paths

### Scanning Activity
- **Threshold**: 5+ 404 responses from same IP
- **Logic**: Detects automated reconnaissance for hidden endpoints

## Technologies Used

### Backend
- **Python 3.x**: Core programming language
- **Flask**: Web framework
- **Gunicorn**: Production WSGI server

### Frontend
- **HTML5/CSS3**: Structure and styling
- **Vanilla JavaScript**: Interactive functionality
- **Chart.js**: Data visualization

### Deployment
- **Render**: Cloud hosting platform


## Running Tests
```bash
python tests/test_parser.py
```

Tests cover:
- Log line parsing
- Brute force detection
- SQL injection detection
- Path traversal detection
- Scanning detection

## What I Learned

### Security Concepts
- Common web attack patterns (OWASP Top 10)
- Log analysis and threat detection methodologies
- Pattern recognition for identifying malicious activity
- Security monitoring and incident detection

### Technical Skills
- Flask web development and RESTful API design
- Regular expressions for pattern matching
- Data visualization with Chart.js
- File upload handling and validation
- Writing unit tests for security functions
- Deploying Python applications to production

### Real-World Applications
- Understanding how Security Operations Centers (SOCs) detect threats
- Log analysis techniques used by security analysts
- Automated threat detection and alerting systems

## Documentation

- [Attack Patterns Explained](docs/attack_patterns.md) - Detailed breakdown of each attack type
- [Sample Logs](static/sample_logs.txt) - Example log file with various attacks

## Deployment

This application can be deployed to Render:

1. Fork this repository
2. Sign up at [Render](https://render.com)
3. Create a new Web Service
4. Connect your GitHub repository
5. Render will automatically detect the Flask app and deploy

The application uses:
- Gunicorn as the production server
- Python 3.11 runtime
- Automatic builds from the main branch


## Author

**Waringa Ngugi**
- GitHub: [@waringangugi](https://github.com/waringangugi)
- Project: [Log Analysis Dashboard](https://github.com/waringangugi/Log-Analysis-Dashboard)

## Future Enhancements

- [ ] Support for more log formats (IIS, custom formats)
- [ ] Email/webhook alerts for critical threats
- [ ] Historical analysis and trend tracking
- [ ] IP geolocation mapping
- [ ] Export reports to PDF
- [ ] Integration with threat intelligence feeds
- [ ] Machine learning for anomaly detection

## Acknowledgments

- OWASP for security best practices and attack documentation
- Chart.js for visualization capabilities
- The cybersecurity community for threat intelligence resources