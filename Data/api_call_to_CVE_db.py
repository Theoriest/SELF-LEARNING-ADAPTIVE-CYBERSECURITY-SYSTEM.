import requests
import pandas as pd
import time

# API endpoint for CVE data (NVD API v2.0)
base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Parameters for pagination
start_index = 0
results_per_page = 2000

filtered_data = []

while True:
    # Create the URL with pagination parameters
    url = f"{base_url}?startIndex={start_index}&resultsPerPage={results_per_page}"
    response = requests.get(url)
    
    if response.status_code == 200:
        # Parse the JSON response
        data = response.json()
        vulnerabilities = data.get("vulnerabilities", [])
        total_results = data.get("totalResults", 0)
        
        # Log the number of records fetched and the total results available
        print(f"Fetched {len(vulnerabilities)} records, Total available: {total_results}")
        
        if not vulnerabilities:
            # If no more vulnerabilities are returned, break the loop
            break
        
        for vuln in vulnerabilities:
            cve = vuln.get("cve", {})
            
            # Extract CVE Identifier
            cve_id = cve.get("id", "")
            
            # Extract the English description
            descriptions = cve.get("descriptions", [])
            description_text = ""
            for desc in descriptions:
                if desc.get("lang") == "en":
                    description_text = desc.get("value", "")
                    break
            
            # Extract CVSS Score from CVSS Metric V3.1 (if available)
            metrics = cve.get("metrics", {})
            cvss_score = None
            if "cvssMetricV31" in metrics:
                cvss_list = metrics.get("cvssMetricV31", [])
                if cvss_list:
                    cvss_data = cvss_list[0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore", None)
            
            # Extract the publication date
            published_date = cve.get("published", "")
            
            # Extract references (list of URLs)
            references = cve.get("references", {})
            reference_urls = [ref.get("url", "") for ref in references]
            
            # Append the filtered CVE data to the list
            filtered_data.append({
                "CVE_ID": cve_id,
                "Description": description_text,
                "CVSS_Score": cvss_score,
                "Published": published_date,
                "References": reference_urls
            })
        
        # Update the start index for the next page
        start_index += results_per_page
        
        # Break the loop if we have fetched all available records
        if start_index >= total_results:
            break
    else:
        print(f"API request failed with status code {response.status_code}")
        # Implementing a wait time if API rate limit is hit
        time.sleep(60)
        continue

# Convert the filtered data into a Pandas DataFrame
df = pd.DataFrame(filtered_data)

# Print the first 5 rows of the DataFrame
print(df.head(5))
# Print the total number of records fetched
print(f"Total records fetched: {len(df)}")