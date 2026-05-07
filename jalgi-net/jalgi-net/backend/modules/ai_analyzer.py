"""
JalgiNet – AI Analysis Module
===============================
Provides security summaries and impact analysis using Google Gemini AI.
"""

import os
import google.generativeai as genai
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

# Configure the Gemini API
API_KEY = os.getenv("GEMINI_API_KEY", "YOUR_FREE_GEMINI_API_KEY")
genai.configure(api_key=API_KEY)

# Use a lightweight model for fast, free-tier analysis
MODEL_NAME = "gemini-1.5-flash"

def analyze_threat(ip, attack_chain, event_count, risk_score):
    """
    Generate an AI summary for a correlated threat.
    Returns a dict with: summary, security_impact, recommended_actions
    """
    if not config.MODULES.get("ai_analysis", True):
        return {
            "summary": "AI analysis disabled.",
            "security_impact": "N/A",
            "recommended_actions": "N/A"
        }

    if API_KEY == "YOUR_FREE_GEMINI_API_KEY":
        return {
            "summary": f"Threat detected from {ip} following pattern: {' -> '.join(attack_chain)}.",
            "security_impact": "Potential compromise of targeted services or network availability.",
            "recommended_actions": "Verify IP reputation and consider blocking if behavior continues."
        }

    prompt = f"""
    As a cybersecurity expert, analyze the following SOC threat and provide a concise summary,
    its security impact, and recommended actions.

    Device (IP): {ip}
    Attack Chain: {' -> '.join(attack_chain)}
    Total Events: {event_count}
    Risk Score: {risk_score}/10

    Format your response EXACTLY as follows:
    Summary: [One sentence summary]
    Impact: [One sentence security impact]
    Actions: [Bullet points of recommended actions]
    """

    try:
        model = genai.GenerativeModel(MODEL_NAME)
        response = model.generate_content(prompt)
        text = response.text.strip()

        # Simple parsing of the response
        summary = ""
        impact = ""
        actions = ""

        for line in text.split('\n'):
            if line.startswith("Summary:"):
                summary = line.replace("Summary:", "").strip()
            elif line.startswith("Impact:"):
                impact = line.replace("Impact:", "").strip()
            elif line.startswith("Actions:"):
                actions = line.replace("Actions:", "").strip()
            elif actions and line.strip(): # Capture bullet points if needed
                actions += "\n" + line.strip()

        return {
            "summary": summary or "Threat detected from " + ip,
            "security_impact": impact or "Potential network security risk.",
            "recommended_actions": actions or "Monitor this IP closely."
        }
    except Exception as e:
        print(f"[AI] Error during analysis: {e}")
        return {
            "summary": f"Failed to generate AI summary for {ip}.",
            "security_impact": "Unknown",
            "recommended_actions": "Manual investigation required."
        }

def summarize_device(ip, activity_summary):
    """
    Summarize the overall risk and behavior of a specific device.
    """
    if API_KEY == "YOUR_FREE_GEMINI_API_KEY":
        return f"Device {ip} has been involved in multiple security events. Current status requires monitoring."

    prompt = f"""
    Summarize the security profile of the following device based on its recent activity:
    Device: {ip}
    Activity: {activity_summary}

    Provide a 2-3 sentence overview of what this device is doing and how it affects overall security.
    """

    try:
        model = genai.GenerativeModel(MODEL_NAME)
        response = model.generate_content(prompt)
        return response.text.strip()
    except Exception as e:
        print(f"[AI] Error during device summary: {e}")
        return "Manual device review recommended."
