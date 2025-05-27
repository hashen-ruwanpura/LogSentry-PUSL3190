# LogSentry


## 🔍 Overview

A comprehensive security platform that monitors Apache and MySQL server logs in real-time to detect threats, classify them according to the MITRE ATT&CK framework, and deliver timely notifications across multiple channels. The platform employs advanced pattern matching, anomaly detection, and machine learning algorithms to identify suspicious activities while providing predictive maintenance capabilities to ensure system health and predictive appraoch to future attacks.

## 🌟 Core Components

### 1. Advanced Log Analysis Engine
- **Sophisticated Pattern Recognition**: Processes Apache and MySQL logs using signature-based detection
- **Scoring Mechanism**: Assigns threat scores (0-100) to suspicious activities
- **Contextual Analysis**: Evaluates log content within the broader system context
- **Normalization Pipeline**: Transforms diverse log formats into standardized structures

### 2. Real-time Threat Detection
- **Multi-layered Detection Approach**: Combines rule-based detection with machine learning
- **MITRE ATT&CK Integration**: Maps threats to industry-standard tactics and techniques
- **Historical Pattern Analysis**: Correlates current activity with previous attack patterns
- **Anomaly Detection**: Identifies statistical deviations from established baselines

### 3. Intelligent Alerting System
- **Multi-channel Notifications**: Email, SMS, and push notifications via Firebase
- **Severity-based Prioritization**: Customizable alert thresholds based on threat severity
- **Deduplication Logic**: Prevents alert fatigue by identifying duplicate notifications
- **Interactive Alert Interface**: Allows security teams to acknowledge and manage alerts

### 4. Predictive Maintenance
- **System Resource Monitoring**: Tracks CPU, memory, disk usage with trend analysis
- **Resource Exhaustion Prediction**: Calculates time until critical thresholds are reached
- **Log Volume Management**: Monitors log growth and implements automatic rotation
- **AI-based Analysis**: Provides recommendations for system optimization

### 5. AI-Powered Analysis
- **Threat Intelligence Reports**: Generates comprehensive security assessments
- **Pattern Recognition**: Identifies attack campaigns and prevalent tactics
- **Contextual Recommendations**: Provides actionable security advice
- **User-Configurable Reports**: Customizable based on preferences and filters

### 6. MITRE ATT&CK Classification
- **5-Layer Classification Process**: Hierarchical approach to threat categorization
- **Tactic and Technique Mapping**: Identifies specific attack methodologies
- **Interactive MITRE Dashboard**: Visualizes threat distribution across the framework
- **Evolving Pattern Detection**: Tracks changes in attack tactics over time

### 7. Informative Admin Panel
- **User Management**: Add users and configure access permissions
- **Automated Onboarding**: Sends interactive emails with login credentials
- **Support Interface**: Admin user support page for user assistance
- **Audit Trail**: Monitors file changes and configuration modifications

## ✨ Key Features

### Security Monitoring
- **Real-time Log Analysis**: Continuous monitoring of Apache and MySQL server logs
- **Threat Intelligence Integration**: Enriches threat data with information from AbuseIPDB and VirusTotal
- **Geographic Attack Visualization**: Maps attack origins to their geographic locations using GEOLite2
- **Historical Correlation**: Links new threats with previously observed patterns

### Notifications & Alerts
- **Custom Alert Thresholds**: Configure notification preferences based on severity
- **Real-time Push Notifications**: Firebase integration for instant mobile alerts
- **Detailed Threat Context**: Rich information about each security incident
- **Escalation Workflows**: Automated processes for critical security events

### System Management
- **Log Volume Management**: Monitors log growth and implements automatic rotation
- **Automated Maintenance Tasks**: Scheduling of system optimization operations
- **Performance Monitoring**: Tracks system resource utilization over time
- **Health Dashboard**: Visualizes system status and performance metrics

### Reporting & Analytics
- **Interactive Dashboards**: Visual representation of security metrics and trends
- **Custom Report Generation**: Export capabilities in multiple formats (PDF, CSV, JSON)
- **Historical Data Analysis**: Track security posture changes over time
- **Executive Summaries**: High-level security overviews for management

## 🔧 Technical Architecture

The platform employs a modular architecture with specialized components:

- **Log Ingestion**: Collects and normalizes logs from various sources
- **Threat Detection**: Analyzes normalized logs using rules and ML algorithms
- **Alert Management**: Processes detected threats and generates appropriate alerts
- **Notification Delivery**: Distributes alerts across configured channels
- **MITRE Mapping**: Classifies threats according to the ATT&CK framework
- **Predictive Analytics**: Monitors system health and predicts maintenance needs
- **Report Generation**: Creates comprehensive security reports and visualizations

## 📊 Threat Classification Process

The platform uses a sophisticated 5-layer approach to map threats to the MITRE ATT&CK framework:

1. **Exact Attack Pattern Matching**: Direct mapping of detected attack patterns
2. **Content-Based Pattern Matching**: Analysis of log content for known signatures
3. **Attack Type Classification**: Mapping general attack types to MITRE categories
4. **Contextual Analysis**: Intelligent inference based on extracted context
5. **URL Heuristics**: Analysis of URL patterns when other methods fail

Threats are assigned severity levels (low, medium, high, critical) based on:
- Attack score calculation
- Pattern matching results
- Context (admin paths, sensitive endpoints)
- Known malicious IP reputation
- MITRE ATT&CK tactics and techniques

## 🚀 Installation

### Prerequisites
- Python 3.8+
- MySQL or SQLite
- Node.js (for frontend assets)
- Apache and MySQL servers for monitoring

### Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/yourusername/LogSentry.git
   cd LogSentry
   ```

2. **Create a virtual environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Configure environment variables**:
   - Copy `.env.example` to `.env`
   - Update the variables with your configuration

5. **Initialize the database**:
   ```bash
   python manage.py migrate
   ```

6. **Create an admin user**:
   ```bash
   python manage.py createsuperuser
   ```

7. **Generate Firebase service worker** (for push notifications):
   ```bash
   node gen-firebase-sw.js
   ```

8. **Run the server**:
   ```bash
   python manage.py runserver
   ```

## 💡 Usage Guide

### Connecting Log Sources

1. Navigate to **Settings > Log Sources**
2. Configure the paths to your Apache and MySQL log files
3. Test connections to ensure logs are accessible
4. Enable real-time processing if desired

### Monitoring Threats

1. The **Dashboard** provides an overview of system security status
2. **Threats** page shows detailed information about detected security issues
3. Use filters to focus on specific threat types, severities, or time periods
4. View geographic distribution on the attack map

### Managing Alerts

1. Configure notification preferences in **Settings > Notifications**
2. Set minimum severity thresholds for different notification channels
3. Add email addresses or mobile numbers for alert delivery
4. Test notifications to verify proper setup

### System Maintenance

1. Visit the **Predictive Maintenance** page to view system health
2. Monitor resource usage trends and forecasts
3. Schedule recommended maintenance tasks
4. Configure automated log rotation to prevent disk exhaustion

### Analyzing Security Posture

1. Use the **Reports** section to generate comprehensive security analyses
2. Review AI-generated insights about your threat landscape
3. Export reports for documentation or compliance purposes
4. Track security metrics over time to identify trends

## 🔐 Enhancing Security

### Threat Intelligence Integration

The platform integrates with external threat intelligence sources:

1. **AbuseIPDB**: Provides IP reputation scoring based on reported abuse
2. **VirusTotal**: Offers malware detection and URL/domain reputation data

These integrations enhance threat detection by:
- Increasing severity for known malicious sources
- Providing additional context for security analysis
- Enabling more accurate classification of threats
- Supporting automated blacklisting recommendations

### Advanced Anomaly Detection

The system establishes baselines of normal behavior and detects deviations:

1. Statistical analysis of historical log patterns
2. Identification of unusual request patterns or volumes
3. Detection of abnormal execution times or response sizes
4. Correlation of events across different log sources

## 🌐 Technologies Used

- **Backend**: Django (Python), MySQL/SQLite
- **Frontend**: HTML5, CSS3, JavaScript, Bootstrap 5
- **Visualization**: Chart.js, jVectorMap
- **Notifications**: Firebase Cloud Messaging, SMTP
- **Machine Learning**: Anomaly detection algorithms
- **Security**: MITRE ATT&CK framework, AbuseIPDB, VirusTotal
- **Reporting**: PDF generation (jsPDF), CSV/JSON exports

## 📁 Project Structure

The platform is organized into several Django apps:

- **authentication**: User management and preferences
- **log_ingestion**: Log collection and normalization
- **threat_detection**: Analysis and threat identification
- **alerts**: Notification generation and delivery
- **ai_analytics**: AI-powered security insights
- **frontend**: User interface templates and assets
- **siem**: Security information and event management
- **reports**: Reporting and visualization components

## 📜 License

This project is licensed under the MIT License.

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📞 Support

For questions, feature requests, or issues, please open an issue on the GitHub repository.

---

Developed with ❤️ for security professionals and system administrators.