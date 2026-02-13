import requests
import json
import time

url = "http://localhost:8000/api/v1/analyze"
payload = {
    "contract_address": "0xDA7a001b254CD22e46d3eAB04d937489c93174C3",
    "network": "ethereum",
    "force_refresh": True
}

def analyze():
    try:
        print(f"Analyzing {payload['contract_address']}...")
        response = requests.post(url, json=payload)
        response.raise_for_status()
        data = response.json()
        
        with open("analysis_verify.json", "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        
        score = data.get("trust_score", {}).get("overall_score")
        print(f"Overall Score: {score}")
        
        # Print summary of vulns to see if prompt fix worked
        vulns = data.get("vulnerabilities", [])
        for v in vulns:
            print(f"- {v.get('severity')} ({v.get('confidence')}): {v.get('name')}")
            
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    # Wait for server to be ready
    time.sleep(5)
    analyze()
