
import json
import random
from datetime import datetime, timedelta

def generate_mock_data():
    vendors = ["Microsoft", "Apple", "Google", "Adobe", "Oracle", "Cisco", "Linux", "VMware", "AWS", "Kubernetes", "F5", "Fortinet", "Palo Alto Networks", "Citrix", "OpenSSL"]
    products = ["Windows", "macOS", "Chrome", "Acrobat Reader", "Database", "IOS", "Kernel", "ESXi", "EC2", "Cluster", "BIG-IP", "FortiGate", "PAN-OS", "ADC", "Library"]

    nvd_cves = []
    for i in range(50):
        vendor_idx = random.randint(0, len(vendors) - 1)
        vendor = vendors[vendor_idx]
        product = products[vendor_idx]
        score = round(random.uniform(4.0, 10.0), 1)
        severity = "CRITICAL" if score >= 9.0 else "HIGH" if score >= 7.0 else "MEDIUM"
        
        nvd_cves.append({
            "cve": {
                "id": f"CVE-2026-{10000 + i}",
                "descriptions": [{"lang": "en", "value": f"A {severity.lower()} vulnerability in {vendor} {product} allowing for potential exploitation. Vulnerability details for research purposes."}],
                "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": score, "baseSeverity": severity}}]},
                "configurations": [{"nodes": [{"cpeMatch": [{"criteria": f"cpe:2.3:a:{vendor.lower()}:{product.lower()}:1.0:*:*:*:*:*:*:*"}]}]}]
            }
        })

    cisa_kev = []
    for i in range(12):
        vendor_idx = random.randint(0, len(vendors) - 1)
        cisa_kev.append({
            "cveID": f"CVE-2025-{2000 + i}",
            "vendorProject": vendors[vendor_idx],
            "product": products[vendor_idx],
            "shortDescription": f"Active exploitation of {vendors[vendor_idx]} {products[vendor_idx]} vulnerability discovered in the wild.",
            "dueDate": (datetime.now() + timedelta(days=random.randint(-2, 14))).strftime('%Y-%m-%d')
        })

    threats = {
        "nvd_cves": nvd_cves,
        "cisa_kev": cisa_kev,
        "last_updated": datetime.now().isoformat()
    }

    news = {
        "hacker_news": [
            {"title": f"Security Alert: {vendors[random.randint(0, 14)]} vulnerability research", "url": "#", "score": random.randint(100, 600), "by": "sec_expert", "time": datetime.now().isoformat()} for _ in range(5)
        ],
        "reddit_netsec": [
            {"title": f"Deep dive into {products[random.randint(0, 14)]} exploit vector", "url": "#", "score": random.randint(200, 1000), "author": "researcher1", "created_utc": datetime.now().isoformat()} for _ in range(5)
        ],
        "last_updated": datetime.now().isoformat()
    }

    with open("data/threats.json", "w") as f:
        json.dump(threats, f, indent=4)
    with open("data/news.json", "w") as f:
        json.dump(news, f, indent=4)
    print("Improved mock data generated successfully.")

if __name__ == "__main__":
    generate_mock_data()
