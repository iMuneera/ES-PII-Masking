import requests
import base64
import os

def URL_Cheeker(url):
    print(f"Checking URL: {url}")
    API_KEY = os.getenv("API_KEY")
    print(f"API_KEY Loaded: {bool(API_KEY)}")
    if not API_KEY:
        return "Error: API key is not set"
    
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    vt_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"

    headers = {"x-apikey": API_KEY}

    try:
        response = requests.get(vt_url, headers=headers)

        if response.status_code == 200:
            data = response.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            print(stats)
            malicious = stats.get("malicious", 0)
            suspicious = stats.get("suspicious", 0)
            print(f"Malicious: {malicious}, Suspicious: {suspicious}")
            if malicious > 0:
                return "Malicious"
            elif suspicious > 0:
                return "Suspicious"
            else:
                return "Safe"

        else:
            return f"Error: {response.status_code} {response.reason}"

    except Exception as e:
        return f"Error: {str(e)}"
