# Wazuh Alert Analyzer

A powerful Python CLI tool for analyzing Wazuh security alerts with dynamic time ranges, alert level classification, and comprehensive shift reporting. Integrates with OpenSearch backend for large-scale data retrieval and analysis.

## 🚀 Features

### Core Functionality
- **Dynamic Time Range Input** - Flexible date and time configuration with timezone support
- **Alert Level Classification** - Automatic categorization (Low, Medium, High, Critical)
- **Top 5 Alert Analysis** - Most frequent alerts by description with "Others" category
- **Comprehensive Reporting** - Detailed shift summaries with statistics and percentages
- **Large Dataset Support** - Uses OpenSearch scroll API for handling massive alert volumes
- **Timezone Handling** - Proper WIB (UTC+7) to UTC conversion

### Technical Features
- **OpenSearch Integration** - Direct connection to Wazuh's OpenSearch backend
- **Scroll API Support** - Efficient retrieval of large datasets (50k+ alerts)
- **SSL/TLS Support** - Secure HTTPS connections with certificate validation options
- **Error Handling** - Robust error handling and user-friendly messages
- **Report Export** - Automatic report saving to timestamped files

## 📋 Prerequisites

### System Requirements
- Python 3.6 or higher
- Network access to OpenSearch server
- Wazuh deployment with OpenSearch backend

### Python Dependencies
```bash
pip install requests urllib3
```

### Required Access
- OpenSearch server credentials
- Access to `wazuh-alerts-*` indices
- Network connectivity to OpenSearch port (default: 9200)

## ⚙️ Configuration

### 1. Edit Script Configuration
Before running, update the credentials section in the script:

```python
# CREDENTIALS - UPDATE THESE VALUES
OPENSEARCH_HOST = "your-opensearch-server"  # Replace with your server IP/hostname
OPENSEARCH_PORT = "9200"                    # Default OpenSearch port
OPENSEARCH_USER = "your-username"           # Your OpenSearch username
OPENSEARCH_PASSWORD = "your-password"       # Your OpenSearch password
OPENSEARCH_USE_HTTPS = True                 # True for HTTPS, False for HTTP
```

### 2. Network Configuration
Ensure your system can reach:
- OpenSearch server on the configured port
- Wazuh indices are accessible via the specified credentials

## 🎯 Usage

### Basic Usage
```bash
python opensearch-simple-github.py
```

### Interactive Configuration
The script will prompt for:
1. **Analysis Date** - Target date for analysis (default: today)
2. **Start Time** - Beginning of analysis period (format: HH:MM)
3. **End Time** - End of analysis period (format: HH:MM)
4. **Confirmation** - Review and confirm settings before execution

### Example Session
```
🛡️  Wazuh Alert Analyzer - OpenSearch Version
============================================================
🔗 Connecting to: https://your-server:9200
👤 Using credentials: admin:***

ANALYSIS TIME CONFIGURATION
========================================
Enter date (YYYY-MM-DD), default: [2025-08-24]: 2025-08-24
START TIME CONFIGURATION
Enter start time (HH:MM), default: [08:00]: 08:00
END TIME CONFIGURATION  
Enter end time (HH:MM), default: [17:00]: 17:00

📋 CONFIGURATION SUMMARY:
Date: 2025-08-24
Time WIB (GMT+7): 08:00 - 17:00
Time UTC: 2025-08-24T01:00:00Z - 2025-08-24T10:00:00Z

Continue with this configuration? (y/n) [y]: y
```

## 📊 Output Format

### Console Report
The tool generates a detailed console report with:
- **Report Header** - Timestamp and analysis period
- **Alert Statistics** - Total alerts and distribution by severity
- **Top 5 Alerts** - Most frequent alert types with counts and percentages
- **Others Category** - Summary of remaining alert types

### Example Output
```
╔════════════════════════════════════════════════════════════╗
║                    WAZUH ALERT SHIFT SUMMARY              ║
╠════════════════════════════════════════════════════════════╣
║ Report Generated: 2025-08-24 15:30:45
║ Analysis Period: 2025-08-24 08:00:00 to 2025-08-24 17:00:00
║ Time Zone: WIB (UTC+7)
╠════════════════════════════════════════════════════════════╣
│ ALERT STATISTICS:
│ Total Alerts During Analysis: 64,563
│
│ DISTRIBUTION BY SEVERITY:
│ • Low (0-6):      45,231 alerts (70.1%)
│ • Medium (7-11):  15,687 alerts (24.3%)
│ • High (12-14):    2,891 alerts (4.5%)
│ • Critical (15+):    754 alerts (1.2%)
│
│ TOP 5 MOST FREQUENT ALERTS:
│ 1. Windows Logon Success
│    Count: 12,543 (19.4%)
│
│ 2. SSH Authentication Success  
│    Count: 8,932 (13.8%)
│
│ 3. File Integrity Monitoring Alert
│    Count: 6,721 (10.4%)
│
│ 4. Network Connection Established
│    Count: 4,856 (7.5%)
│
│ 5. Process Creation Event
│    Count: 3,442 (5.3%)
│
│ 6. Others (remaining alert types)
│    Count: 28,069 (43.5%)
│
╚════════════════════════════════════════════════════════════╝
```

### File Export
Reports are automatically saved as:
```
wazuh_shift_report_opensearch_YYYYMMDD_HHMMSS.txt
```

## 🔧 Alert Classification

### Severity Levels
The tool automatically classifies alerts based on Wazuh rule levels:

| Classification | Rule Levels | Description |
|----------------|-------------|-------------|
| **Low** | 0-6 | Informational events, routine activities |
| **Medium** | 7-11 | Notable events requiring attention |
| **High** | 12-14 | Important security events |
| **Critical** | 15+ | Critical security incidents |

### Analysis Features
- **Percentage Distribution** - Shows proportion of each severity level
- **Top 5 Analysis** - Most frequent alert descriptions
- **Others Category** - Aggregate of remaining alerts beyond top 5
- **Count Statistics** - Exact numbers with comma formatting

## 🛠️ Troubleshooting

### Common Issues

#### Connection Problems
```
❌ OpenSearch connection failed: HTTP 401
```
**Solution:** Check username/password in configuration

#### No Data Returned
```
❌ No alerts found for the specified time range
```
**Possible Causes:**
- Time range has no alerts
- Incorrect timezone conversion
- Index pattern mismatch
- Network connectivity issues

#### SSL Certificate Issues
```
❌ SSL Certificate verification failed
```
**Solution:** The script disables SSL warnings by default, but ensure HTTPS settings match your server configuration

#### Large Dataset Timeouts
```
❌ Error during scroll: timeout
```
**Solution:** The script uses scroll API for large datasets. Check network stability and OpenSearch server performance.

### Debug Tips
1. **Test Connection First** - The script automatically tests connectivity
2. **Check Time Zones** - Ensure WIB timezone is appropriate for your location
3. **Verify Indices** - Confirm `wazuh-alerts-*` indices exist and are accessible
4. **Monitor Resources** - Large time ranges may require significant memory

## 📁 File Structure
```
├── opensearch-simple-github.py    # Main script
├── README.md                       # This documentation
└── wazuh_shift_report_*           # Generated reports (auto-created)
```

## 🔒 Security Considerations

### Data Protection
- **No Credential Storage** - Configure credentials directly in script
- **Local Processing** - All analysis performed locally
- **Report Security** - Reports contain aggregated data, not raw alert content
