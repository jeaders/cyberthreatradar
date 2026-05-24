
import requests
import json
import time
import os
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta

# Mapping geografico dei vendor per il Radar
VENDOR_LOCATIONS = {
    "microsoft": {"lat": 47.6740, "lng": -122.1215, "country": "USA"},
    "google": {"lat": 37.4220, "lng": -122.0841, "country": "USA"},
    "apple": {"lat": 37.3349, "lng": -122.0090, "country": "USA"},
    "cisco": {"lat": 37.4084, "lng": -121.9540, "country": "USA"},
    "oracle": {"lat": 37.5295, "lng": -122.2530, "country": "USA"},
    "adobe": {"lat": 37.3307, "lng": -121.8940, "country": "USA"},
    "linux": {"lat": 45.5231, "lng": -122.6765, "country": "Global"},
    "apache": {"lat": 33.4484, "lng": -112.0740, "country": "USA"},
    "nginx": {"lat": 37.7749, "lng": -122.4194, "country": "USA"},
    "ibm": {"lat": 41.1225, "lng": -73.7125, "country": "USA"},
    "vmware": {"lat": 37.4024, "lng": -122.1481, "country": "USA"},
    "fortinet": {"lat": 37.3752, "lng": -122.0297, "country": "USA"},
    "ivanti": {"lat": 40.5247, "lng": -111.8638, "country": "USA"},
    "atlassian": {"lat": -33.8688, "lng": 151.2093, "country": "Australia"},
    "sap": {"lat": 49.2933, "lng": 8.6419, "country": "Germany"},
    "qnap": {"lat": 25.0330, "lng": 121.5654, "country": "Taiwan"},
    "synology": {"lat": 25.0478, "lng": 121.5170, "country": "Taiwan"},
    "d-link": {"lat": 25.0792, "lng": 121.5888, "country": "Taiwan"},
    "tp-link": {"lat": 22.5431, "lng": 114.0579, "country": "China"},
    "hikvision": {"lat": 30.2741, "lng": 120.1551, "country": "China"},
}

def fetch_world_news_rss():
    """Recupera news reali dal mondo via BBC RSS"""
    rss_url = "http://feeds.bbci.co.uk/news/world/rss.xml"
    try:
        print("Fetching real world news from BBC RSS...")
        response = requests.get(rss_url, timeout=20)
        response.raise_for_status()
        
        root = ET.fromstring(response.content)
        news_list = []
        
        for item in root.findall('.//item')[:10]:
            title = item.find('title').text
            description = item.find('description').text
            link = item.find('link').text
            pub_date = item.find('pubDate').text
            
            # Immagine di fallback basata sul contenuto (semplificato)
            img = "https://images.unsplash.com/photo-1585829365234-781f8c429215?auto=format&fit=crop&w=800&q=80"
            if "war" in title.lower() or "conflict" in title.lower():
                img = "https://images.unsplash.com/photo-1517048676732-d65bc937f952?auto=format&fit=crop&w=800&q=80"
            elif "tech" in title.lower() or "digital" in title.lower():
                img = "https://images.unsplash.com/photo-1518770660439-4636190af475?auto=format&fit=crop&w=800&q=80"

            news_list.append({
                "title": title,
                "description": description,
                "url": link,
                "source": "BBC News",
                "date": pub_date,
                "img": img
            })
        return news_list
    except Exception as e:
        print(f"Error fetching RSS news: {e}")
        return []

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
    # User-Agent più specifico per evitare 403
    headers = {"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 CyberThreatRadar/2.1"}
    try:
        print("Fetching Reddit r/netsec data...")
        response = requests.get(reddit_url, headers=headers, timeout=20)
        if response.status_code == 403:
            print("Reddit blocked access (403). Trying alternative security news...")
            return []
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
    session = requests.Session()
    session.headers.update(get_nvd_headers())
    
    # 1. Recupera CISA KEV prima per avere una lista di CVE critiche reali
    cisa_kev_data = fetch_cisa_kev_data()
    kev_vulnerabilities = cisa_kev_data.get("vulnerabilities", []) if cisa_kev_data else []

    # 2. Recupera i dettagli NVD per le prime 20 CVE del catalogo CISA (ridotto da 40 per velocità)
    print(f"Fetching NVD details for top 20 KEV vulnerabilities...")
    nvd_cves = []
    cve_ids_for_epss = []
    
    # Usiamo un subset più piccolo per evitare di bloccare l'azione GitHub
    target_kev = kev_vulnerabilities[:20]
    for i, vuln in enumerate(target_kev):
        cve_id = vuln.get("cveID")
        print(f"[{i+1}/{len(target_kev)}] Fetching details for {cve_id}...")
        
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        try:
            response = session.get(url, timeout=15)
            if response.status_code == 200:
                data = response.json()
                vulns = data.get("vulnerabilities", [])
                if vulns:
                    nvd_cves.append(vulns[0])
                    cve_ids_for_epss.append(cve_id)
            elif response.status_code == 403:
                print(f"API Key limit/error for {cve_id}. Skipping remaining NVD detail fetches.")
                break
        except Exception as e:
            print(f"Error fetching {cve_id}: {e}")
            
        time.sleep(0.6) # Rate limit NVD API più prudente

    # 3. Recupera score EPSS per le CVE trovate
    epss_data = fetch_epss_data(cve_ids_for_epss)
    
    # Integriamo EPSS e Posizione Geografica nei dati NVD
    for item in nvd_cves:
        cve_id = item["cve"]["id"]
        # EPSS
        if cve_id in epss_data:
            item["cve"]["epss"] = epss_data[cve_id]
        
        # Posizione Geografica basata sul vendor
        tech = item["cve"].get("configurations", [{}])[0].get("nodes", [{}])[0].get("cpeMatch", [{}])[0].get("criteria", "")
        vendor = tech.split(':')[3].lower() if len(tech.split(':')) > 3 else "unknown"
        
        if vendor in VENDOR_LOCATIONS:
            item["cve"]["location"] = VENDOR_LOCATIONS[vendor]
        else:
            # Fallback randomico ma limitato a zone plausibili se il vendor è ignoto
            item["cve"]["location"] = {
                "lat": (time.time() % 60) - 30, # Genera un numero semi-stabile
                "lng": (time.time() % 360) - 180,
                "country": "Unknown"
            }

    # 4. Recupera news con log di progresso
    print("Fetching news from HackerNews, Reddit and BBC RSS...")
    hn_news = fetch_hacker_news_data()
    reddit_news = fetch_reddit_netsec_data()
    world_news = fetch_world_news_rss()

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
        "world_news_real": world_news, # Aggiunte news reali
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
