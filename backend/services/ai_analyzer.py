import ollama
import json

class AIAnalyzer:
    """
    Module for local AI text analysis using Ollama (Phi-3).
    Detects social engineering and psychological manipulation in emails.
    """

    def __init__(self,model_name="phi3"):
        self.model_name = model_name
    
    def analyze_text(self, text):
        """Analyzes email plain text and returns a JSON assessment."""
        if not text or len(text.strip()) < 10:
            return {"error" : "Text too short for analysis"}
        
        safe_text = text[:3000]

        prompt = f"""
        You are a Senior SOC Analyst expert in social engineering.
        Analyze the following email text for phishing indicators, urgency, and manipulation.
        
        Respond ONLY with a valid JSON object matching this schema:
        {{
            "urgency_level": <integer from 1 to 10>,
            "financial_pressure": <boolean true/false>,
            "manipulation_tactics": [<list of strings describing tactics found, e.g., "Fear", "Authority">],
            "ai_verdict": <string "Safe", "Suspicious", or "Malicious">,
            "brief_reason": <string 1 sentence explaining the verdict>
        }}

        Email text to analyze:
        {safe_text}
        """

        try:
            response = ollama.chat(
                model = self.model_name,
                messages= [{'role': 'user','content': prompt}],
                format='json'
            )

            result_dict = json.loads(response['message']['content'])
            return result_dict
        except json.JSONDecodeError:
            return{"error": "AI failed to generate valid JSON"}
        except Exception as e:
            return {"error": f"Ollama connection error:{str(e)}"}



