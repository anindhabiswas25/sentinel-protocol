import requests
import json
import time

url = "http://localhost:8000/api/v1/analyze"
# USDT Address - previously whitelisted
payload = {
    "contract_address": "0xdac17f958d2ee523a2206206994597c13d831ec7",
    "network": "ethereum",
    "force_refresh": True
}

def analyze():
    try:
        print(f"Analyzing USDT {payload['contract_address']} (Pure Analysis)...")
        response = requests.post(url, json=payload)
        response.raise_for_status()
        data = response.json()
        
        score = data.get("trust_score", {}).get("overall_score")
        print(f"USDT Overall Score: {score}")
        
        # Check LLM insights to see if it recognized it correctly
        print(f"LLM Insights: {data.get('summary', {}).get('llm_insights')[:200]}...")
        
        vulns = data.get("vulnerabilities", [])
        for v in vulns:
            print(f"- {v.get('severity')} ({v.get('confidence')}): {v.get('name')}")
            
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    time.sleep(5)
    analyze()
