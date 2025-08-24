import requests
import urllib3
import json
from datetime import datetime, timedelta
from collections import Counter
import sys
import os

# Disable SSL warnings
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# CREDENTIALS
OPENSEARCH_HOST = "localhost"
OPENSEARCH_PORT = "9200"
OPENSEARCH_USER = "USERNAME"
OPENSEARCH_PASSWORD = "PASSWORD"
OPENSEARCH_USE_HTTPS = True

# URL OpenSearch
OPENSEARCH_URL = f"{'https' if OPENSEARCH_USE_HTTPS else 'http'}://{OPENSEARCH_HOST}:{OPENSEARCH_PORT}"


def get_user_input_time_range():

    print("\nANALYSIS TIME CONFIGURATION")
    print("=" * 40)
    
    today = datetime.now().date()
    while True:
        date_input = input(f"Enter date (YYYY-MM-DD), default: [{today}]: ").strip()
        if date_input == "":
            target_date = today
            break
        else:
            try:
                target_date = datetime.strptime(date_input, "%Y-%m-%d").date()
                break
            except ValueError:
                print("❌ Wrong date format! Use format YYYY-MM-DD (example: 2025-08-24)")
    
    # Start time
    print(f"\nSTART TIME")
    print("Enter start time (format: HH:MM:SS)")
    print("Example: 08:00:00 for 8 AM")
    
    while True:
        start_time_input = input("Start time [08:00:00]: ").strip()
        if start_time_input == "":
            start_time_input = "08:00:00"
        
        try:
            start_time_obj = datetime.strptime(start_time_input, "%H:%M:%S").time()
            break
        except ValueError:
            print("❌ Wrong time format! Use format HH:MM:SS (example: 08:00:00)")
    
    # End time
    print(f"\nEND TIME")
    print("Enter end time (format: HH:MM:SS)")
    print("Example: 17:00:00 for 5 PM")
    
    while True:
        end_time_input = input("End time [17:00:00]: ").strip()
        if end_time_input == "":
            end_time_input = "17:00:00"
        
        try:
            end_time_obj = datetime.strptime(end_time_input, "%H:%M:%S").time()
            break
        except ValueError:
            print("❌ Wrong time format! Use format HH:MM:SS (example: 17:00:00)")
    
    # Time validation (ensure end > start)
    start_datetime_wib = datetime.combine(target_date, start_time_obj)
    end_datetime_wib = datetime.combine(target_date, end_time_obj)
    
    if end_datetime_wib <= start_datetime_wib:
        print("⚠️ End time must be greater than start time!")
        # If end time is smaller, assume next day
        end_datetime_wib = datetime.combine(target_date + timedelta(days=1), end_time_obj)
        print(f"✅ Using end time next day: {end_datetime_wib.strftime('%Y-%m-%d %H:%M:%S')} WIB")
    
    # Convert to UTC (WIB = UTC+7)
    # you can adjust the offset if needed
    start_datetime_utc = start_datetime_wib - timedelta(hours=7)
    end_datetime_utc = end_datetime_wib - timedelta(hours=7)
    
    # ISO format with Z suffix
    start_iso = start_datetime_utc.strftime('%Y-%m-%dT%H:%M:%SZ')
    end_iso = end_datetime_utc.strftime('%Y-%m-%dT%H:%M:%SZ')
    
    # Show summary
    print(f"\nCONFIGURATION SUMMARY:")
    print(f"Date: {target_date}")
    print(f"Time WIB (GMT+7): {start_time_input} - {end_time_input}")
    print(f"Time UTC: {start_iso} - {end_iso}")
    
    # Confirmation
    while True:
        confirm = input("\nContinue with this configuration? (y/n) [y]: ").strip().lower()
        if confirm == "" or confirm == "y" or confirm == "yes":
            break
        elif confirm == "n" or confirm == "no":
            print("❌ Analysis cancelled")
            return None, None
        else:
            print("❌ Answer with 'y' or 'n'")
    
    return start_iso, end_iso, start_datetime_wib, end_datetime_wib

def get_shift_time_range():
    
    today = datetime.now().date()
    
    start_time_utc = datetime.combine(today, datetime.min.time().replace(hour=1, minute=0, second=0))
    end_time_utc = datetime.combine(today, datetime.min.time().replace(hour=10, minute=0, second=0))
    
    # Convert to ISO format with Z suffix for UTC
    start_iso = start_time_utc.strftime('%Y-%m-%dT%H:%M:%SZ')
    end_iso = end_time_utc.strftime('%Y-%m-%dT%H:%M:%SZ')
    
    return start_iso, end_iso

def classify_alert_level(level):
    """
    Classify alert level based on level number
    - Low: 0-6
    - Medium: 7-11  
    - High: 12-14
    - Critical: 15+
    """
    level = int(level) if level is not None else 0
    
    if 0 <= level <= 6:
        return "Low"
    elif 7 <= level <= 11:
        return "Medium"
    elif 12 <= level <= 14:
        return "High"
    elif level >= 15:
        return "Critical"
    else:
        return "Unknown"

def test_opensearch_connection():
    """Test OpenSearch connection"""
    print("🔍 Testing OpenSearch connection...")
    
    auth = (OPENSEARCH_USER, OPENSEARCH_PASSWORD)
    
    try:
        response = requests.get(
            OPENSEARCH_URL,
            auth=auth,
            verify=False,
            timeout=10
        )
        
        if response.status_code == 200:
            data = response.json()
            print(f"✅ OpenSearch connected successfully!")
            print(f"   Cluster: {data.get('cluster_name', 'Unknown')}")
            print(f"   Version: {data.get('version', {}).get('number', 'Unknown')}")
            return True
        else:
            print(f"❌ OpenSearch connection failed: {response.status_code}")
            print(f"   Response: {response.text[:200]}")
            return False
            
    except Exception as e:
        print(f"❌ OpenSearch connection error: {e}")
        return False

def get_wazuh_indices():
    """Get list of available Wazuh indices"""
    print("Getting Wazuh indices...")
    
    auth = (OPENSEARCH_USER, OPENSEARCH_PASSWORD)
    url = f"{OPENSEARCH_URL}/_cat/indices/wazuh-alerts-*?v&s=index"
    
    try:
        response = requests.get(url, auth=auth, verify=False, timeout=10)
        
        if response.status_code == 200:
            indices_text = response.text.strip()
            if indices_text and "health" in indices_text:
                lines = indices_text.split('\\n')
                indices = []
                
                for line in lines[1:]:  # Skip header
                    if line.strip():
                        parts = line.split()
                        if len(parts) >= 3:
                            index_name = parts[2]
                            doc_count = parts[6] if len(parts) > 6 else "0"
                            indices.append({
                                'name': index_name,
                                'doc_count': doc_count
                            })
                
                print(f"✅ Found {len(indices)} Wazuh indices")
                for idx in indices[:3]:  # Show first 3
                    print(f"   - {idx['name']} ({idx['doc_count']} docs)")
                
                return [idx['name'] for idx in indices]
            else:
                print("❌ No Wazuh indices found")
                return []
        else:
            print(f"❌ Failed to get indices: {response.status_code}")
            return []
            
    except Exception as e:
        print(f"❌ Error getting indices: {e}")
        return []

def get_alerts_from_opensearch(start_time, end_time):
    """
    Get alerts from OpenSearch for specific time range
    Using scroll API to get all data
    """
    print(f"📊 Fetching alerts from {start_time} to {end_time}...")
    
    auth = (OPENSEARCH_USER, OPENSEARCH_PASSWORD)
    
    # First, count total alerts without rule.level filter
    count_query_no_filter = {
        "query": {
            "range": {
                "@timestamp": {
                    "gte": start_time,
                    "lte": end_time
                }
            }
        }
    }
    
    count_url = f"{OPENSEARCH_URL}/wazuh-alerts-*/_count"
    
    # Get total count without filter
    try:
        count_response_no_filter = requests.post(
            count_url,
            auth=auth,
            json=count_query_no_filter,
            headers={'Content-Type': 'application/json'},
            verify=False,
            timeout=30
        )
        
        if count_response_no_filter.status_code == 200:
            total_count_no_filter = count_response_no_filter.json().get('count', 0)
            print(f"📊 Total events in time range (no filter): {total_count_no_filter:,}")
        else: 
            total_count_no_filter = 0
    except Exception as e:
        total_count_no_filter = 0
    
    # Second, count total alerts with rule.level filter
    count_query = {
        "query": {
            "bool": {
                "must": [
                    {
                        "range": {
                            "@timestamp": {
                                "gte": start_time,
                                "lte": end_time
                            }
                        }
                    }
                ],
                "filter": [
                    {
                        "exists": {
                            "field": "rule.level"
                        }
                    }
                ]
            }
        }
    }
    
    # Get total count
    count_url = f"{OPENSEARCH_URL}/wazuh-alerts-*/_count"
    try:
        count_response = requests.post(
            count_url,
            auth=auth,
            json=count_query,
            headers={'Content-Type': 'application/json'},
            verify=False,
            timeout=30
        )
        
        if count_response.status_code == 200:
            total_count = count_response.json().get('count', 0)
            print(f"Total alerts in time range: {total_count:,}")
        else:
            print(f"⚠️ Could not get count, proceeding anyway...")
            total_count = 0
    except Exception as e:
        print(f"⚠️ Count query failed: {e}")
        total_count = 0
    
    # Query with scroll to get all data
    all_alerts = []
    batch_size = 5000  # Batch size for each scroll
    
    # Initial search with scroll
    scroll_query = {
        "size": batch_size,
        "query": {
            "bool": {
                "must": [
                    {
                        "range": {
                            "@timestamp": {
                                "gte": start_time,
                                "lte": end_time
                            }
                        }
                    }
                ],
                "filter": [
                    {
                        "exists": {
                            "field": "rule.level"
                        }
                    }
                ]
            }
        },
        "sort": [
            {
                "@timestamp": {
                    "order": "desc"
                }
            }
        ],
        "_source": [
            "@timestamp",
            "rule.level",
            "rule.description", 
            "rule.id",
            "agent.name",
            "agent.ip",
            "location"
        ]
    }
    
    # URL untuk search dengan scroll
    search_url = f"{OPENSEARCH_URL}/wazuh-alerts-*/_search?scroll=5m"
    
    try:
        print(f"Starting data retrieval in batches of {batch_size:,}...")
        
        # Initial search
        response = requests.post(
            search_url,
            auth=auth,
            json=scroll_query,
            headers={'Content-Type': 'application/json'},
            verify=False,
            timeout=60
        )
        
        if response.status_code != 200:
            print(f"❌ Initial search failed: {response.status_code}")
            return []
        
        data = response.json()
        scroll_id = data.get('_scroll_id')
        hits = data.get('hits', {}).get('hits', [])
        
        # Process first batch
        batch_count = 1
        for hit in hits:
            source = hit['_source']
            alert = {
                'timestamp': source.get('@timestamp'),
                'rule_level': source.get('rule', {}).get('level'),
                'rule_description': source.get('rule', {}).get('description'),
                'rule_id': source.get('rule', {}).get('id'),
                'agent_name': source.get('agent', {}).get('name'),
                'agent_ip': source.get('agent', {}).get('ip'),
                'location': source.get('location')
            }
            all_alerts.append(alert)
        
        print(f"   Batch {batch_count}: {len(hits):,} alerts (Total: {len(all_alerts):,})")
        
        # Continue scrolling until no more data
        while hits and len(hits) > 0:
            scroll_url = f"{OPENSEARCH_URL}/_search/scroll"
            scroll_data = {
                "scroll": "5m",
                "scroll_id": scroll_id
            }
            
            scroll_response = requests.post(
                scroll_url,
                auth=auth,
                json=scroll_data,
                headers={'Content-Type': 'application/json'},
                verify=False,
                timeout=60
            )
            
            if scroll_response.status_code != 200:
                print(f"❌ Scroll failed: {scroll_response.status_code}")
                break
            
            scroll_result = scroll_response.json()
            scroll_id = scroll_result.get('_scroll_id')
            hits = scroll_result.get('hits', {}).get('hits', [])
            
            if not hits:
                break
                
            # Process this batch
            batch_count += 1
            for hit in hits:
                source = hit['_source']
                alert = {
                    'timestamp': source.get('@timestamp'),
                    'rule_level': source.get('rule', {}).get('level'),
                    'rule_description': source.get('rule', {}).get('description'),
                    'rule_id': source.get('rule', {}).get('id'),
                    'agent_name': source.get('agent', {}).get('name'),
                    'agent_ip': source.get('agent', {}).get('ip'),
                    'location': source.get('location')
                }
                all_alerts.append(alert)
            
            print(f"   Batch {batch_count}: {len(hits):,} alerts (Total: {len(all_alerts):,})")
            
            # Safety limit untuk menghindari infinite loop
            if batch_count > 50:  # Max 50 batches = 250k alerts
                print(f"⚠️ Reached safety limit of {batch_count} batches")
                break
        
        # Clear scroll
        if scroll_id:
            try:
                clear_url = f"{OPENSEARCH_URL}/_search/scroll"
                requests.delete(
                    clear_url,
                    auth=auth,
                    json={"scroll_id": [scroll_id]},
                    headers={'Content-Type': 'application/json'},
                    verify=False,
                    timeout=10
                )
            except:
                pass  # Ignore errors when clearing scroll
        
        print(f"✅ Successfully retrieved {len(all_alerts):,} alerts")
        if total_count > 0 and len(all_alerts) != total_count:
            print(f"⚠️ Retrieved {len(all_alerts):,} out of {total_count:,} total alerts")
        
        return all_alerts
            
    except Exception as e:
        print(f"❌ Error searching alerts: {e}")
        return []

def analyze_alerts(alerts):
    """
    Analyze alert data and generate report
    """
    if not alerts:
        print("❌ No alerts to analyze")
        return None
    
    print(f"📈 Analyzing {len(alerts)} alerts...")
    
    # Klasifikasi berdasarkan level
    level_counts = {"Low": 0, "Medium": 0, "High": 0, "Critical": 0}
    rule_descriptions = []
    
    for alert in alerts:
        level = alert.get('rule_level', 0)
        classification = classify_alert_level(level)
        level_counts[classification] += 1
        
        description = alert.get('rule_description', 'Unknown')
        if description and description != 'Unknown':
            rule_descriptions.append(description)
    
    # Total alerts
    total_alerts = len(alerts)
    
    # Hitung persentase
    level_percentages = {}
    for level, count in level_counts.items():
        percentage = (count / total_alerts * 100) if total_alerts > 0 else 0
        level_percentages[level] = percentage
    
    # Top 5 alert descriptions
    description_counter = Counter(rule_descriptions)
    top_5_descriptions = description_counter.most_common(5)
    
    return {
        'total_alerts': total_alerts,
        'level_counts': level_counts,
        'level_percentages': level_percentages,
        'top_5_descriptions': top_5_descriptions,
    }

def generate_report(analysis, start_wib=None, end_wib=None, start_utc=None, end_utc=None):
    """
    Menghasilkan laporan dalam format yang mudah dibaca
    """
    if not analysis:
        return "❌ No analysis data available"
    
    # Jika tidak ada parameter waktu, gunakan default
    if start_wib is None or end_wib is None:
        start_time, end_time = get_shift_time_range()
        start_wib_str = "08:00:00 WIB (2025-08-24)"
        end_wib_str = "17:00:00 WIB (2025-08-24)"
        utc_range = f"{start_time} to {end_time}"
    else:
        start_wib_str = start_wib.strftime('%H:%M:%S WIB (%Y-%m-%d)')
        end_wib_str = end_wib.strftime('%H:%M:%S WIB (%Y-%m-%d)')
        utc_range = f"{start_utc} to {end_utc}"
    
    report_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    
    report = f"""
╔══════════════════════════════════════════════════════════════════════
║                      WAZUH ALERT SUMMARY
║                      OpenSearch Version
╠══════════════════════════════════════════════════════════════════════
║ Report Generated: {report_time}
║ Time Period: {start_wib_str} to {end_wib_str}
║ Data Source: OpenSearch ({OPENSEARCH_HOST}:{OPENSEARCH_PORT})
║ Query Range (UTC): {utc_range}
╚══════════════════════════════════════════════════════════════════════

📊 ALERT STATISTICS:
┌─────────────────────────────────────────────────────────────────────
│ Total Alerts During Time Period: {analysis['total_alerts']:,}
└─────────────────────────────────────────────────────────────────────

🎯 ALERT DISTRIBUTION BY LEVEL:
┌─────────────────────────────────────────────────────────────────────
│ Critical (15+)  : {analysis['level_counts']['Critical']:>6,} alerts ({analysis['level_percentages']['Critical']:>6.1f}%)
│ High (12-14)    : {analysis['level_counts']['High']:>6,} alerts ({analysis['level_percentages']['High']:>6.1f}%)
│ Medium (7-11)   : {analysis['level_counts']['Medium']:>6,} alerts ({analysis['level_percentages']['Medium']:>6.1f}%)
│ Low (0-6)       : {analysis['level_counts']['Low']:>6,} alerts ({analysis['level_percentages']['Low']:>6.1f}%)
└─────────────────────────────────────────────────────────────────────

🔝 TOP 5 MOST FREQUENT ALERTS:
┌─────────────────────────────────────────────────────────────────────"""

    # Hitung total dari top 5
    top_5_total = sum(count for _, count in analysis['top_5_descriptions'])
    others_count = analysis['total_alerts'] - top_5_total
    others_percentage = (others_count / analysis['total_alerts'] * 100) if analysis['total_alerts'] > 0 else 0

    for i, (description, count) in enumerate(analysis['top_5_descriptions'], 1):
        percentage = (count / analysis['total_alerts'] * 100) if analysis['total_alerts'] > 0 else 0
        report += f"\n│ {i}. {description[:60]}"
        if len(description) > 60:
            report += "..."
        report += f"\n│    Count: {count:,} ({percentage:.1f}%)\n│"

    # Tambahkan kategori "Others" untuk sisa alerts
    if others_count > 0:
        report += f"\n│ 6. Others (remaining alert types)"
        report += f"\n│    Count: {others_count:,} ({others_percentage:.1f}%)\n│"

    report += """
└─────────────────────────────────────────────────────────────────────

═══════════════════════════════════════════════════════════════════════
                            END OF REPORT
═══════════════════════════════════════════════════════════════════════
"""
    
    return report

def main():
    """Main function"""
    print("🛡️  Wazuh Alert Summary - OpenSearch Version")
    print("=" * 60)
    print(f"🔗 Connecting to: {OPENSEARCH_URL}")
    print(f"👤 Using credentials: {OPENSEARCH_USER}:***")
    
    # Test connection
    if not test_opensearch_connection():
        print("❌ Cannot connect to OpenSearch. Please check:")
        print("   1. OpenSearch is running on port 9200")
        print("   2. Credentials are correct")
        print("   3. Network connectivity")
        return
    
    # Get indices
    # indices = get_wazuh_indices()
    # if not indices:
    #     print("⚠️  No Wazuh indices found, but continuing...")
    
    # Get time range from user input
    result = get_user_input_time_range()
    if result[0] is None:  # User cancelled
        return
    
    start_time, end_time, start_wib, end_wib = result
    print(f"⏰ Final time range: {start_time} to {end_time}")
    
    # Fetch alerts
    alerts = get_alerts_from_opensearch(start_time, end_time)
    
    if not alerts:
        print("❌ No alerts found for the specified time range")
        print("   This could mean:")
        print("   1. No alerts occurred during the specified time")
        print("   2. Index pattern doesn't match")
        print("   3. Time range format issue")
        return
    
    # Analyze alerts
    analysis = analyze_alerts(alerts)
    
    if not analysis:
        print("❌ Failed to analyze alerts")
        return
    
    # Generate and display report with custom time range
    report = generate_report(analysis, start_wib, end_wib, start_time, end_time)
    print(report)
    
    # Save report to file
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    date_str = start_wib.strftime('%Y%m%d')
    filename = f"wazuh_shift_report_opensearch_{date_str}_{timestamp}.txt"
    
    try:
        with open(filename, 'w', encoding='utf-8') as f:
            f.write(report)
        print(f"💾 Report saved to: {filename}")
    except Exception as e:
        print(f"⚠️  Could not save report to file: {e}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\n⏹️ Program stopped by user")
    except Exception as e:
        print(f"\n❌ Unexpected error: {e}")
        import traceback
        traceback.print_exc()
