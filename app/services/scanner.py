import re
from typing import List, Dict, Any
from sqlalchemy.orm import Session
from app.models import ScamPattern

DEFAULT_PATTERNS = [
    # --- FEE_SCAM / IMPERSONATION PATTERNS ---
    {"pattern": r"registration\s+fee", "type": "regex", "scam_type": "fee_scam", "weight": "high", "title": "Registration Fee Demanded", "desc": "Legitimate employers never demand a registration or application fee."},
    {"pattern": r"security\s+deposit", "type": "regex", "scam_type": "fee_scam", "weight": "high", "title": "Security Deposit Required", "desc": "Asking for money before or upon joining is a classic job scam tactic."},
    {"pattern": r"refundable\s+deposit", "type": "regex", "scam_type": "fee_scam", "weight": "high", "title": "Refundable Deposit Mentioned", "desc": "Scammers claim deposits are 'refundable' to gain trust before stealing funds."},
    {"pattern": r"processing\s+fee", "type": "regex", "scam_type": "fee_scam", "weight": "high", "title": "Processing / Document Fee", "desc": "Real companies cover their own HR & onboarding paperwork costs."},
    {"pattern": r"reply\s+YES", "type": "regex", "scam_type": "fee_scam", "weight": "medium", "title": "Bulk SMS / Automated 'Reply YES' Hook", "desc": "Generic spam recruitment messages asking to reply YES or click WhatsApp links."},
    {"pattern": r"send\s+(your\s+)?aadhaar|send\s+pan\s+card", "type": "regex", "scam_type": "fee_scam", "weight": "high", "title": "Pre-Interview Identity Document Request", "desc": "Requesting sensitive identity documents (Aadhaar/PAN) before a formal interview poses identity theft risks."},
    {"pattern": r"no\s+interview\s+required|direct\s+selection", "type": "regex", "scam_type": "fee_scam", "weight": "high", "title": "No Technical / Formal Interview Required", "desc": "Immediate job offers without real multi-step interviews or technical evaluations are highly suspicious."},
    {"pattern": r"selected\s+immediately|congratulations\s+you\s+(have\s+been|are)\s+selected", "type": "regex", "scam_type": "fee_scam", "weight": "high", "title": "Instant Unsolicited Selection", "desc": "Claims of instant selection without prior formal application or interview."},
    {"pattern": r"telegram\s+(hr|contact|group|channel|task)", "type": "regex", "scam_type": "fee_scam", "weight": "high", "title": "Telegram Recruitment / Task Scam", "desc": "Conducting hiring or daily tasks exclusively over Telegram is a known scam vector."},
    {"pattern": r"training\s+kit\s+fee|laptop\s+deposit", "type": "regex", "scam_type": "fee_scam", "weight": "high", "title": "Equipment / Training Fee", "desc": "Employers provide equipment; employees should never pay for company laptops or training kits."},
    
    # --- GHOST_LISTING / DATA_HARVESTING PATTERNS ---
    {"pattern": r"forms\.gle|docs\.google\.com/forms|typeform\.com", "type": "regex", "scam_type": "ghost_listing", "weight": "high", "title": "Off-Platform Third-Party Data Capture Form", "desc": "Asking candidates to apply via public Google Forms/Typeform rather than a corporate career portal or ATS."},
    {"pattern": r"previous\s+salary\s+slip|last\s+3\s+months\s+bank\s+statement", "type": "regex", "scam_type": "ghost_listing", "weight": "high", "title": "Pre-Interview Financial Document Harvest", "desc": "Requesting bank statements or salary slips before any shortlist or interview stage."},
    {"pattern": r"continuous\s+recruitment|always\s+hiring|pool\s+building", "type": "regex", "scam_type": "ghost_listing", "weight": "medium", "title": "Continuous Resume Harvesting / Ghost Pipeline", "desc": "Listings kept open perpetually to build resume databases rather than fill an active headcount vacancy."},
    {"pattern": r"upload\s+(aadhaar|passport|bank\s+passbook)\s+to\s+apply", "type": "regex", "scam_type": "ghost_listing", "weight": "high", "title": "Disproportionate Initial Application Data Request", "desc": "Mandating sensitive government IDs at the raw resume submission phase."}
]

def scan_text_for_red_flags(text: str, db: Session = None) -> Dict[str, Any]:
    text_lower = text.lower()
    matched_flags = []
    fee_scam_count = 0
    ghost_listing_count = 0

    # 1. Check DB ScamPatterns if database session provided
    db_patterns = []
    if db:
        try:
            db_patterns = db.query(ScamPattern).all()
        except Exception:
            db_patterns = []

    if db_patterns:
        for pat in db_patterns:
            matched = False
            if pat.pattern_type == "regex":
                if re.search(pat.pattern_text, text_lower, re.IGNORECASE):
                    matched = True
            else:
                if pat.pattern_text.lower() in text_lower:
                    matched = True
            
            if matched:
                scam_cat = pat.scam_type or "fee_scam"
                matched_flags.append({
                    "title": f"Pattern Matched: {pat.pattern_text}",
                    "desc": f"Matched pattern categorized under {scam_cat.upper()}.",
                    "severity": pat.severity_weight or "high",
                    "scam_type": scam_cat
                })
                if scam_cat == "fee_scam":
                    fee_scam_count += 1
                else:
                    ghost_listing_count += 1
    else:
        # Fallback to default regex rules
        for item in DEFAULT_PATTERNS:
            if re.search(item["pattern"], text_lower, re.IGNORECASE):
                matched_flags.append({
                    "title": item["title"],
                    "desc": item["desc"],
                    "severity": item["weight"],
                    "scam_type": item["scam_type"]
                })
                if item["scam_type"] == "fee_scam":
                    fee_scam_count += 1
                else:
                    ghost_listing_count += 1

    # 2. Entity Extraction
    phone_numbers = re.findall(r'(?:\+?91[\-\s]?)?[6-9]\d{9}', text)
    emails = re.findall(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', text)
    urls = re.findall(r'https?://[^\s<>"]+|www\.[^\s<>"]+', text)

    # 3. Extract job title heuristically if present
    job_title_match = re.search(r'(?:role|position|job\s+title|hiring\s+for):\s*([a-zA-Z0-9\s\-]{3,40})', text, re.IGNORECASE)
    detected_title = job_title_match.group(1).strip() if job_title_match else None

    # 4. Extract company name heuristically if present
    company_match = re.search(r'(?:company|client|organization|at):\s*([a-zA-Z0-9\s\-]{3,40})', text, re.IGNORECASE)
    detected_company = company_match.group(1).strip() if company_match else None

    return {
        "red_flags": matched_flags,
        "fee_scam_count": fee_scam_count,
        "ghost_listing_count": ghost_listing_count,
        "extracted_phones": list(set(phone_numbers)),
        "extracted_emails": list(set(emails)),
        "extracted_urls": list(set(urls)),
        "detected_title": detected_title,
        "detected_company": detected_company
    }
