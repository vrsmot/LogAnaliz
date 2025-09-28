import requests
import logging

def check_ip(ip, api_key):
    url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
    headers = {"x-apikey": api_key}
    r = requests.get(url, headers=headers, timeout=15)
    if r.status_code == 200:
        return r.json()["data"]["attributes"]["last_analysis_stats"]
    logging.error(f"Ошибка {r.status_code} при проверке IP {ip}")
    return {"status": "error"}

def check_hash(h, api_key):
    url = f"https://www.virustotal.com/api/v3/files/{h}"
    headers = {"x-apikey": api_key}
    r = requests.get(url, headers=headers, timeout=15)
    if r.status_code == 200:
        return r.json()["data"]["attributes"]["last_analysis_stats"]
    logging.error(f"Ошибка {r.status_code} при проверке HASH {h}")
    return {"status": "error"}
