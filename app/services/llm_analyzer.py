import json
import asyncio
from typing import Dict, Any, List
import anthropic
from app.config import settings

SYSTEM_PROMPT = """You are an expert cybersecurity and employment fraud analyst for ScamCheck.
Your task is to analyze job postings, recruiter communications, SMS, emails, or offer letters and classify them into two distinct categories:

CATEGORY 1: FEE_SCAM / IDENTITY_THEFT (impersonation, upfront fees, registration charges, instant selection without interview, identity document theft).
CATEGORY 2: GHOST_LISTING / DATA_HARVESTING (phantom postings designed to harvest applicant resumes/data for AI training, resale, or pipeline building without hiring intent, off-platform Google/Typeforms, excessive pre-interview document requests).

YOU MUST RESPOND strictly with valid JSON matching this schema:
{
    "scam_type": "fee_scam" | "ghost_listing" | "phishing_portal" | "unclear" | "likely_legitimate",
    "risk_score": "high" | "medium" | "low",
    "confidence": 85,
    "red_flags": [
        "Demands ₹1,500 registration fee before interview",
        "Uses Google Form for initial application instead of corporate ATS"
    ],
    "explanation": "A concise 1-2 sentence summary explaining the primary classification and risk reason."
}
Do NOT wrap your output in markdown backticks or include any conversational intro/outro text outside JSON.
"""

def _call_claude_sync(text: str, model_name: str) -> Dict[str, Any]:
    if not settings.ANTHROPIC_API_KEY:
        return {"success": False, "reason": "No API key configured"}
    
    try:
        client = anthropic.Anthropic(api_key=settings.ANTHROPIC_API_KEY)
        response = client.messages.create(
            model=model_name,
            max_tokens=1000,
            temperature=0.1,
            system=SYSTEM_PROMPT,
            messages=[
                {"role": "user", "content": f"Analyze this job message/posting text for scam & ghost-listing patterns:\n\n{text}"}
            ]
        )
        content_text = response.content[0].text.strip()
        if content_text.startswith("```"):
            content_text = content_text.split("```")[1]
            if content_text.startswith("json"):
                content_text = content_text[4:]
            content_text = content_text.strip()
            
        data = json.loads(content_text)
        return {
            "success": True,
            "scam_type": data.get("scam_type", "fee_scam").lower(),
            "risk_score": data.get("risk_score", "medium").lower(),
            "confidence": int(data.get("confidence", 70)),
            "red_flags": data.get("red_flags", []),
            "explanation": data.get("explanation", "Analyzed using Anthropic Claude LLM model.")
        }
    except Exception as e:
        if model_name != "claude-3-5-sonnet-20241022":
            try:
                return _call_claude_sync(text, "claude-3-5-sonnet-20241022")
            except Exception:
                pass
        return {"success": False, "error": str(e)}

async def analyze_with_llm(text: str) -> Dict[str, Any]:
    """Asynchronous caller for Anthropic Claude analysis."""
    if not settings.ANTHROPIC_API_KEY or len(text.strip()) < 10:
        return {"success": False, "reason": "Skipped LLM (API key omitted or short text)"}
    
    model_to_use = settings.ANTHROPIC_MODEL or "claude-sonnet-4-6"
    return await asyncio.to_thread(_call_claude_sync, text, model_to_use)

def merge_rule_and_llm_signals(
    rule_results: Dict[str, Any], 
    llm_results: Dict[str, Any],
    domain_results: List[Dict[str, Any]],
    crowdsource_results: Dict[str, Any],
    ats_info: Dict[str, Any] = None
) -> Dict[str, Any]:
    """
    Combine rule-based scanner, domain checks, ATS analysis, crowdsource matches, and LLM output.
    Rule-based hard red flags override LLM toward "high risk".
    """
    combined_red_flags = []
    
    for flag in rule_results.get("red_flags", []):
        combined_red_flags.append({
            "title": flag["title"],
            "desc": flag["desc"],
            "severity": flag["severity"],
            "scam_type": flag.get("scam_type", "fee_scam"),
            "source": "Rule Engine"
        })
        
    for d_flag in domain_results:
        if d_flag and d_flag.get("title"):
            combined_red_flags.append({
                "title": d_flag["title"],
                "desc": d_flag["desc"],
                "severity": d_flag.get("severity", "high"),
                "scam_type": d_flag.get("scam_type", "fee_scam"),
                "source": "Domain Intelligence"
            })

    # ATS check flag
    if ats_info and ats_info.get("is_third_party_form"):
        combined_red_flags.append({
            "title": ats_info["title"],
            "desc": ats_info["desc"],
            "severity": "high",
            "scam_type": "ghost_listing",
            "source": "ATS Verification"
        })

    # Crowdsource flags
    if crowdsource_results.get("has_matches"):
        combined_red_flags.append({
            "title": crowdsource_results["title"],
            "desc": crowdsource_results["desc"],
            "severity": crowdsource_results["severity"],
            "scam_type": "fee_scam",
            "source": "Community Reports"
        })

    # Ghost listing posting history flag
    posting_hist = crowdsource_results.get("posting_history")
    if posting_hist and posting_hist.get("is_ghost_candidate"):
        combined_red_flags.append({
            "title": f"High Repost Frequency ({posting_hist['repost_count']}x)",
            "desc": f"This exact job title for {posting_hist['company_name']} has been reposted repeatedly ({posting_hist['repost_count']} times) over {posting_hist['days_open']} days without hiring resolution.",
            "severity": "high",
            "scam_type": "ghost_listing",
            "source": "Posting Frequency Tracker"
        })

    # LLM signals
    llm_explanation = ""
    llm_score = "low"
    llm_confidence = 50
    llm_scam_type = "unclear"

    if llm_results.get("success"):
        llm_score = llm_results.get("risk_score", "low")
        llm_confidence = llm_results.get("confidence", 75)
        llm_explanation = llm_results.get("explanation", "")
        llm_scam_type = llm_results.get("scam_type", "fee_scam")

        for reason in llm_results.get("red_flags", []):
            if not any(f["title"] == reason for f in combined_red_flags):
                combined_red_flags.append({
                    "title": reason,
                    "desc": "AI pattern analysis identified this suspicious element.",
                    "severity": "high" if llm_score == "high" else "medium",
                    "scam_type": llm_scam_type,
                    "source": "Claude AI"
                })

    # Rule Counts
    fee_rules = rule_results.get("fee_scam_count", 0)
    ghost_rules = rule_results.get("ghost_listing_count", 0)
    has_typosquat_or_recent = any(df.get("severity") == "high" and df.get("scam_type") == "fee_scam" for df in domain_results if df)
    is_third_party_form = ats_info.get("is_third_party_form") if ats_info else False

    # DETERMINE FINAL SCAM TYPE
    if ghost_rules > fee_rules or is_third_party_form or (posting_hist and posting_hist.get("is_ghost_candidate")):
        final_scam_type = "ghost_listing"
    elif fee_rules > 0 or has_typosquat_or_recent:
        final_scam_type = "fee_scam"
    elif llm_scam_type != "unclear":
        final_scam_type = llm_scam_type
    else:
        final_scam_type = "fee_scam"

    # DETERMINE FINAL RISK SCORE & CONFIDENCE
    if fee_rules > 0 or ghost_rules > 0 or has_typosquat_or_recent or is_third_party_form or (posting_hist and posting_hist.get("is_ghost_candidate")):
        final_risk = "high"
        confidence = max(90, llm_confidence if llm_results.get("success") else 85)
        if not llm_explanation:
            llm_explanation = f"High risk detected: Matched critical {final_scam_type.upper().replace('_', ' ')} warning indicators."
    elif llm_score == "high":
        final_risk = "high"
        confidence = llm_confidence
    elif llm_score == "medium" or crowdsource_results.get("has_matches"):
        final_risk = "medium"
        confidence = llm_confidence if llm_results.get("success") else 70
        if not llm_explanation:
            llm_explanation = "Medium risk detected: Contains suspicious phrasing or unverified posting patterns."
    else:
        final_risk = "low"
        confidence = llm_confidence if llm_results.get("success") else 80
        if not llm_explanation:
            llm_explanation = "Low risk detected. Application uses standard recruitment format without upfront fees or ghost listing flags."
            final_scam_type = "likely_legitimate"

    return {
        "scam_type": final_scam_type,
        "risk_score": final_risk,
        "confidence": confidence,
        "red_flags": combined_red_flags,
        "explanation": llm_explanation
    }
