
import requests
from datetime import datetime, timedelta

today = datetime.now()
# Proviamo con un range di 10 giorni nel 2024
url = "https://services.nvd.nist.gov/rest/json/cves/2.0?lastModStartDate=2024-03-01T00:00:00.000&lastModEndDate=2024-03-10T00:00:00.000"

print(f"Testing URL: {url}")
try:
    response = requests.get(url, timeout=20)
    print(f"Status Code: {response.status_code}")
    if response.status_code == 200:
        data = response.json()
        print(f"Total results: {data.get('totalResults')}")
        if data.get('vulnerabilities'):
            print(f"First CVE ID: {data['vulnerabilities'][0]['cve']['id']}")
    else:
        print(f"Response: {response.text}")
except Exception as e:
    print(f"Error: {e}")
