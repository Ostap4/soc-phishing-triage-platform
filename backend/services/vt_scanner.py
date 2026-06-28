import os
import requests
import base64
from dotenv import load_dotenv

class VTScanner:
    """
    Module for querying the VirusTotal v3 API for URL and Hash reputation.
    """
    def __init__(self):
       
        load_dotenv()
        self.api_key = os.getenv("VT_API_KEY")
        
        if not self.api_key:
            print("WARNING: VT_API_KEY is not set in .env file!")
            
        self.base_url = "https://www.virustotal.com/api/v3"
        self.headers = {
            "accept": "application/json",
            "x-apikey": self.api_key
        }

    def get_url_report(self, url):
        """Fetches the reputation report for a specific URL."""
        if not self.api_key:
            return {"url": url, "error": "No API key configured"}

       
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        endpoint = f"{self.base_url}/urls/{url_id}"

        try:
            response = requests.get(endpoint, headers=self.headers)
            
            if response.status_code == 200:
                data = response.json()
                stats = data['data']['attributes']['last_analysis_stats']
                
                
                return {
                    "url": url,
                    "malicious": stats.get('malicious', 0),
                    "suspicious": stats.get('suspicious', 0),
                    "undetected": stats.get('undetected', 0),
                    "status": "Success"
                }
            elif response.status_code == 404:
                
                return {"url": url, "status": "Not found in database"}
            elif response.status_code == 429:
                return {"url": url, "error": "Rate limit exceeded (Too many requests)"}
            else:
                return {"url": url, "error": f"HTTP {response.status_code}"}
                
        except Exception as e:
            return {"url": url, "error": str(e)}
        
    def get_hash_report(self, file_hash):
        """Fetches the reputation report for a specific file hash (SHA-256, MD5, etc.)."""
        if not self.api_key:
            return {"hash": file_hash, "error": "No API key configured"}
        
        endpoint = f"{self.base_url}/files/{file_hash}"

        try:
            response = requests.get(endpoint, headers=self.headers)
            if response.status_code == 200:
                data = response.json()
                stats = data['data']['attributes']['last_analysis_stats']

                return {
                    "hash": file_hash,
                    "malicious": stats.get('malicious', 0),
                    "suspicious": stats.get('suspicious', 0),
                    "undetected": stats.get('undetected', 0),
                    "status": "Success"

                }
            elif response.status_code == 404:
                
                return {"hash": file_hash, "status": "Not found in database (Unknown file)"}
            elif response.status_code == 429:
                return {"hash": file_hash, "error": "Rate limit exceeded"}
            else:
                return {"hash": file_hash, "error": f"HTTP {response.status_code}"}
                
        except Exception as e:
            return {"hash": file_hash, "error": str(e)}

