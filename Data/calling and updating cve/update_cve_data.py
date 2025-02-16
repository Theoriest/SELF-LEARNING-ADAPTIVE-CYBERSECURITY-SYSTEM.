import requests
import pandas as pd
import time

# API endpoints for CVE data and history (NVD API v2.0)
base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
history_url = "https://services.nvd.nist.gov/rest/json/cvehistory/2.0"

csv_file_path = "Data/csv_files/cve_data.csv"

# Function to fetch CVE data for a specific CVE ID and return as a dictionary
def fetch_cve_data_by_id(cve_id):
    url = f"{base_url}?cveId={cve_id}"
    response = requests.get(url)
    
    if response.status_code == 200:
        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])
        
        if vulnerabilities:
            cve = vulnerabilities[0].get("cve", {})
            cve_id = cve.get("id", "")
            descriptions = cve.get("descriptions", [])
            description_text = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description_text = desc.get("value", "")
                    break
            
            metrics = cve.get("metrics", {})
            cvss_score = None
            if "cvssMetricV31" in metrics:
                cvss_list = metrics.get("cvssMetricV31", [])
                if cvss_list:
                    cvss_data = cvss_list[0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore", None)
            
            published_date = cve.get("published", "")
            references = cve.get("references", {})
            reference_urls = [ref.get("url", "") for ref in references]
            
            return {
                "CVE_ID": cve_id,
                "Description": description_text,
                "CVSS_Score": cvss_score,
                "Published": published_date,
                "References": reference_urls
            }
    else:
        print(f"API request failed with status code {response.status_code}")
        time.sleep(60)
        return None

# Function to fetch CVE history and return as a list of dictionaries
def fetch_cve_history():
    response = requests.get(history_url)
    
    if response.status_code == 200:
        data = response.json()
        changes = data.get("changes", [])
        
        print(f"Fetched {len(changes)} change records")
        
        return changes
    else:
        print(f"API request failed with status code {response.status_code}")
        time.sleep(60)
        return []

# Load existing data
df = pd.read_csv(csv_file_path)

# Fetch CVE history
changes = fetch_cve_history()

# Apply changes to the DataFrame
for change in changes:
    cve_id = change.get("cve", {}).get("id", "")
    action = change.get("action", "")
    
    if action == "DELETE":
        df = df[df["CVE_ID"] != cve_id]
    else:
        # Fetch updated CVE data for the specific CVE ID
        updated_record = fetch_cve_data_by_id(cve_id)
        if updated_record:
            df = df[df["CVE_ID"] != cve_id]  # Remove old record if exists
            df = df.append(updated_record, ignore_index=True)  # Add updated record

# Save updated DataFrame to CSV file
df.to_csv(csv_file_path, mode='w', header=True, index=False)
print(f"Data updated in {csv_file_path}")
print(f"Total records in CSV: {len(df)}")