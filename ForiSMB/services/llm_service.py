import os
import google.generativeai as genai


class LLMService:
    def __init__(self, model_name: str = "gemini-2.0-flash"):
        api_key = os.getenv("GEMINI_API_KEY")

        if not api_key:
            raise ValueError("GEMINI_API_KEY is not set in environment variables.")

        genai.configure(api_key=api_key)

        self.model = genai.GenerativeModel(model_name)

    def explain_risk(self, payload: dict, prediction_result: dict) -> str:

        prompt = f"""
You are a cybersecurity risk explanation assistant.

User AI query:
{payload.get("ai_query", "")}

Input event:
- action: {payload.get("action")}
- fortismb_role: {payload.get("fortismb_role")}
- file_op: {payload.get("file_op")}
- is_usb: {payload.get("is_usb")}
- hour: {payload.get("hour")}
- off_hours: {payload.get("off_hours")}
- date: {payload.get("date")}

Prediction result:
{prediction_result}

Explain the detected risk in a short professional way.
Mention:
1. Why behavior is risky
2. Risk level
3. Recommended action
Keep response concise.
"""

        try:
            response = self.model.generate_content(prompt)

            if hasattr(response, "text") and response.text:
                return response.text.strip()

            return "No explanation generated."

        except Exception:
            risk = prediction_result.get("final_risk", "Unknown")
            action = prediction_result.get("system_action", "Monitor")

            return (
                f"The activity was classified as {risk} risk. "
                f"The behavior appears suspicious based on Sysmon activity and FortiSMB model output. "
                f"Recommended response: {action}."
            )