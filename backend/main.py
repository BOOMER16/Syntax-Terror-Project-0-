import os
import json
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
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

class AnalyzeResponse(BaseModel):
    threat_name: str
    intent_explanation: str
    deobfuscated_code: str
    yara_rule: str

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
        "explain its intent, identify the threat name, and write a YARA rule for it.\n\n"
        f"Script:\n{request.script}"
    )

    try:
        response = client.models.generate_content(
            model='gemini-2.5-flash',
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
        
        # The response.text is guaranteed to be a JSON string that matches the AnalyzeResponse schema
        return json.loads(response.text)
        
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error generating analysis: {str(e)}")
