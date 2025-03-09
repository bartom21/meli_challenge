from fastapi import FastAPI, HTTPException
import requests
from ciscoconfparse2 import CiscoConfParse
from security.security_analyzer import SecurityAnalyzer
from security.default_rules import default_rules

app = FastAPI()
CONFIG_SERVICE_URL = "http://localhost:8000/config"

@app.post("/analyze")
def analyze_configuration():
    """Fetch config from config-service & analyze security issues."""
    try:
        response = requests.get(CONFIG_SERVICE_URL)
        if response.status_code != 200:
            raise HTTPException(status_code=500, detail="Failed to fetch configuration")

        config_text = response.text
        parse = CiscoConfParse(config_text.splitlines())

        analyzer = SecurityAnalyzer(default_rules)
        findings = analyzer.run(parse)

        return {"status": "completed", "findings": findings or [{"issue": "No security issues detected", "severity": "None"}]}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error analyzing configuration: {str(e)}")
