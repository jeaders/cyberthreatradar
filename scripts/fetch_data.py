
import requests
import json
import time
import os
from datetime import datetime, timedelta

def get_nvd_headers():
    """Restituisce gli header per l'API NVD, includendo la chiave API se disponibile"""
    headers = {}
    api_key = os.environ.get("NVD_API_KEY")
    if api_key:
        headers["apiKey"] = api_key
    return headers

def fetch_nvd_data():
    """Recupera le CVE recenti (simulando date reali per la compatibilità con l'anno 2026)"""
    # Usiamo il 2024 come anno base per le API reali del mondo esterno
    base_year = 2024
    today = datetime.now()
    
    # Creiamo un range di 30 giorni nel 2024 basato sul mese/giorno corrente
    try:
        end_date_dt = datetime(base_year, today.month, today.day)
    except ValueError: # Gestione bisestile o giorni inesistenti
        end_date_dt = datetime(base_year, today.month, 28)
        
    start_date_dt = end_date_dt - timedelta(days=120)
    
    start_date = start_date_dt.strftime('%Y-%m-%dT00:00:00.000')
    end_date = end_date_dt.strftime('%Y-%m-%dT23:59:59.999')
    
    # NVD API 2.0 richiede Start e End date per range ampi
    # Usiamo un range più ampio e nessun filtro di severità per ora, poi filtriamo in Python
    nvd_url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?lastModStartDate={start_date}&lastModEndDate={end_date}&resultsPerPage=500"
    
    try:
        print(f"Fetching real NVD data (simulated range: {start_date} to {end_date})...")
        response = requests.get(nvd_url, headers=get_nvd_headers(), timeout=30)
        if response.status_code == 200:
            data = response.json()
            # Filtriamo per assicurarci di avere metriche, non CVE rimosse e severità rilevante
            all_vulns = data.get("vulnerabilities", [])
            valid_vulnerabilities = []
            for v in all_vulns:
                cve = v.get("cve", {})
                metrics = cve.get("metrics", {})
                cvss_v3 = metrics.get("cvssMetricV31", []) or metrics.get("cvssMetricV30", [])
                
                if cvss_v3 and cve.get("vulnStatus") != "Rejected":
                    # Estraiamo lo score per assicurarci che sia >= 7.0
                    score = cvss_v3[0].get("cvssData", {}).get("baseScore", 0)
                    if score >= 7.0:
                        valid_vulnerabilities.append(v)
            
            data["vulnerabilities"] = valid_vulnerabilities
            if valid_vulnerabilities:
                print(f"Successfully fetched {len(valid_vulnerabilities)} valid real HIGH/CRITICAL CVEs.")
                return data
            else:
                print("No valid HIGH/CRITICAL CVEs found in this range.")
        else:
            print(f"NVD API returned error: {response.status_code}")
    except Exception as e:
        print(f"Error during NVD fetch: {e}")
    
    return None

def fetch_cisa_kev_data():
    """Recupera il catalogo CISA KEV (vulnerabilità sfruttate attivamente)"""
    cisa_kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    try:
        print("Fetching CISA KEV data...")
        response = requests.get(cisa_kev_url, timeout=30)
        response.raise_for_status()
        return response.json()
    except Exception as e:
        print(f"Error fetching CISA KEV data: {e}")
        return None

def fetch_hacker_news_data():
    """Recupera news di sicurezza da HackerNews"""
    hn_top_stories_url = "https://hacker-news.firebaseio.com/v0/topstories.json"
    try:
        print("Fetching HackerNews data...")
        response = requests.get(hn_top_stories_url, timeout=20)
        response.raise_for_status()
        top_story_ids = response.json()

        hn_stories = []
        keywords = ["security", "vulnerability", "exploit", "hack", "breach", "cve", "zero-day", "ransomware", "malware"]

        for story_id in top_story_ids[:100]:
            story_url = f"https://hacker-news.firebaseio.com/v0/item/{story_id}.json"
            try:
                story_response = requests.get(story_url, timeout=5)
                story = story_response.json()
                if story and story.get("url"):
                    title = story.get("title", "").lower()
                    if any(kw in title for kw in keywords):
                        hn_stories.append({
                            "title": story.get("title"),
                            "url": story.get("url"),
                            "score": story.get("score"),
                            "by": story.get("by"),
                            "time": datetime.fromtimestamp(story.get("time", 0)).isoformat()
                        })
            except:
                continue
            if len(hn_stories) >= 10: break
        return hn_stories
    except Exception as e:
        print(f"Error fetching HN data: {e}")
        return []

def fetch_reddit_netsec_data():
    """Recupera post recenti da r/netsec"""
    reddit_url = "https://www.reddit.com/r/netsec/top.json?t=day&limit=25"
    headers = {"User-Agent": "CyberThreatRadar/2.0 (by /u/SecurityResearcher)"}
    try:
        print("Fetching Reddit r/netsec data...")
        response = requests.get(reddit_url, headers=headers, timeout=20)
        response.raise_for_status()
        posts = response.json().get("data", {}).get("children", [])

        reddit_posts = []
        for post in posts:
            data = post["data"]
            reddit_posts.append({
                "title": data.get("title"),
                "url": data.get("url"),
                "score": data.get("score"),
                "author": data.get("author"),
                "created_utc": datetime.fromtimestamp(data.get("created_utc", 0)).isoformat()
            })
        return reddit_posts
    except Exception as e:
        print(f"Error fetching Reddit data: {e}")
        return []

def fetch_nvd_details_for_cve(cve_id):
    """Recupera i dettagli NVD per una singola CVE"""
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
    try:
        response = requests.get(url, headers=get_nvd_headers(), timeout=10)
        if response.status_code == 200:
            data = response.json()
            vulns = data.get("vulnerabilities", [])
            if vulns:
                return vulns[0]
    except:
        pass
    return None

def fetch_epss_data(cve_ids):
    """Recupera gli score EPSS per una lista di CVE"""
    if not cve_ids:
        return {}
    
    # EPSS API permette di interrogare più CVE separate da virgola
    cve_list = ",".join(cve_ids)
    url = f"https://api.first.org/data/v1/epss?cve={cve_list}"
    
    try:
        print(f"Fetching EPSS data for {len(cve_ids)} CVEs...")
        response = requests.get(url, timeout=20)
        if response.status_code == 200:
            data = response.json()
            epss_results = {}
            for item in data.get("data", []):
                epss_results[item["cve"]] = {
                    "epss": item["epss"],
                    "percentile": item["percentile"]
                }
            return epss_results
    except Exception as e:
        print(f"Error fetching EPSS data: {e}")
    return {}

def main():
    # 1. Recupera CISA KEV prima per avere una lista di CVE critiche reali
    cisa_kev_data = fetch_cisa_kev_data()
    kev_vulnerabilities = cisa_kev_data.get("vulnerabilities", []) if cisa_kev_data else []

    # 2. Recupera i dettagli NVD per le prime 40 CVE del catalogo CISA (garantisce dati reali e critici)
    print(f"Fetching NVD details for top 40 KEV vulnerabilities...")
    nvd_cves = []
    cve_ids_for_epss = []
    for vuln in kev_vulnerabilities[:40]:
        cve_id = vuln.get("cveID")
        details = fetch_nvd_details_for_cve(cve_id)
        if details:
            nvd_cves.append(details)
            cve_ids_for_epss.append(cve_id)
        time.sleep(0.4) # Rate limit NVD API

    # 3. Recupera score EPSS per le CVE trovate
    epss_data = fetch_epss_data(cve_ids_for_epss)
    
    # Integriamo EPSS nei dati NVD
    for item in nvd_cves:
        cve_id = item["cve"]["id"]
        if cve_id in epss_data:
            item["cve"]["epss"] = epss_data[cve_id]

    # 4. Recupera news
    hn_news = fetch_hacker_news_data()
    reddit_news = fetch_reddit_netsec_data()

    # Prepariamo i dati delle minacce
    threats_data = {
        "nvd_cves": nvd_cves,
        "cisa_kev": kev_vulnerabilities,
        "last_updated": datetime.now().isoformat(),
        "api_status": {
            "nvd": "online" if nvd_cves else "offline",
            "cisa": "online" if kev_vulnerabilities else "offline",
            "epss": "online" if epss_data else "offline"
        }
    }

    news_data = {
        "hacker_news": hn_news,
        "reddit_netsec": reddit_news,
        "last_updated": datetime.now().isoformat()
    }

    try:
        with open("data/threats.json", "w") as f:
            json.dump(threats_data, f, indent=4)
        print("Real-time threats data saved to data/threats.json")

        with open("data/news.json", "w") as f:
            json.dump(news_data, f, indent=4)
        print("Real-time news data saved to data/news.json")
    except Exception as e:
        print(f"Error saving files: {e}")

if __name__ == "__main__":
    main()
