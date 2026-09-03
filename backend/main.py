import os
import json
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from typing import List
from google import genai
from google.genai import types
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Allows all domains to talk to the backend
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize the Gemini client
# It will automatically pick up the GEMINI_API_KEY environment variable.
client = genai.Client()

class AnalyzeRequest(BaseModel):
    script: str

class TimelinePhase(BaseModel):
    phase_name: str
    description: str

class IOC(BaseModel):
    indicator: str
    type: str
    classification: str

class ThreatProfile(BaseModel):
    adversary_category: str
    technique_pattern: str
    target_objective: str

class AnalyzeResponse(BaseModel):
    threat_name: str
    intent_explanation: str
    deobfuscated_code: str
    yara_rule: str
    risk_score: int
    risk_reason: str
    remediation_steps: List[str]
    attack_timeline: List[TimelinePhase]
    iocs: List[IOC]
    threat_profile: ThreatProfile

@app.get("/")
def read_root():
    return {"status": "ok", "message": "AXON.REV Backend is running! Send a POST request to /analyze or visit /docs for the API schema."}

@app.post("/analyze", response_model=AnalyzeResponse)
def analyze_script(request: AnalyzeRequest):
    if not request.script:
        raise HTTPException(status_code=400, detail="Script content is required.")

    prompt = (
        "You are an expert malware analyst and reverse engineer. "
        "Analyze the following script, deobfuscate it if necessary, "
        "explain its intent, identify the threat name, and write a YARA rule for it.\n"
        "Additionally, evaluate a risk score (0-100), explain the risk reason, "
        "provide exactly 3 actionable remediation steps, construct an attack timeline (up to 4 phases), "
        "extract any IOCs (domains, IPs, files), and build a threat profile (adversary category, technique pattern, objective).\n\n"
        f"Script:\n{request.script}"
    )

    try:
        response = client.models.generate_content(
            model='gemini-3.6-flash',
            contents=prompt,
            config=types.GenerateContentConfig(
                response_mime_type="application/json",
                response_schema=AnalyzeResponse,
                temperature=0.2,
                safety_settings=[
                    types.SafetySetting(
                        category="HARM_CATEGORY_DANGEROUS_CONTENT",
                        threshold="BLOCK_NONE",
                    ),
                    types.SafetySetting(
                        category="HARM_CATEGORY_HARASSMENT",
                        threshold="BLOCK_NONE",
                    ),
                    types.SafetySetting(
                        category="HARM_CATEGORY_HATE_SPEECH",
                        threshold="BLOCK_NONE",
                    ),
                    types.SafetySetting(
                        category="HARM_CATEGORY_SEXUALLY_EXPLICIT",
                        threshold="BLOCK_NONE",
                    ),
                ]
            ),
        )
        
        if hasattr(response, 'parsed') and response.parsed:
            # If the SDK automatically parsed it into the Pydantic model
            return response.parsed
            
        # Fallback manual parsing if response.text has markdown formatting
        text = response.text.strip()
        if text.startswith("```json"):
            text = text[7:]
        elif text.startswith("```"):
            text = text[3:]
        if text.endswith("```"):
            text = text[:-3]
            
        return json.loads(text.strip())
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generating analysis: {str(e)}\nRaw Response (if any): {getattr(response, 'text', 'No response text') if 'response' in locals() else 'None'}")
