import requests
import json

url = "http://localhost:8000/api/v1/analyze"
payload = {
    "contract_address": "0xDA7a001b254CD22e46d3eAB04d937489c93174C3",
    "network": "ethereum",  # Assuming ethereum, but could be others
    "force_refresh": True
}

try:
    print(f"Analyzing {payload['contract_address']}...")
    response = requests.post(url, json=payload)
    response.raise_for_status()
    data = response.json()
    
    with open("analysis.json", "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    
    print("Analysis saved to analysis.json")
    
    score = data.get("trust_score", {}).get("overall_score")
    print(f"\nOverall Score: {score}")
    
except Exception as e:
    print(f"Error: {e}")
    if hasattr(e, 'response') and e.response:
        print(e.response.text)
