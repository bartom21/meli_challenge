from fastapi import FastAPI, HTTPException
from ciscoconfparse2 import CiscoConfParse
from security.security_analyzer import SecurityAnalyzer
from security.default_rules import default_rules
from config_fetcher import fetch_config  # Import the refactored function

app = FastAPI()

@app.post("/analyze")
def analyze_configuration():
    """Fetch config from config-service & analyze security issues."""
    try:
        config_text = fetch_config()  # Use the refactored function

        parse = CiscoConfParse(config_text.splitlines())
        analyzer = SecurityAnalyzer(default_rules)
        findings = analyzer.run(parse)

        return {"status": "completed", "findings": findings or [{"issue": "No security issues detected", "severity": "None"}]}

    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error analyzing configuration: {str(e)}")
