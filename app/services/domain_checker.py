import re
import asyncio
import datetime
import whois
from urllib.parse import urlparse
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from app.models import KnownDomain, ATSDomain

# Major company seed domain list
SEED_LEGIT_DOMAINS = {
    "tcs.com": "Tata Consultancy Services (TCS)",
    "infosys.com": "Infosys",
    "wipro.com": "Wipro",
    "accenture.com": "Accenture",
    "amazon.in": "Amazon India",
    "amazon.com": "Amazon",
    "google.com": "Google",
    "microsoft.com": "Microsoft",
    "hcltech.com": "HCL Technologies",
    "techmahindra.com": "Tech Mahindra",
    "cognizant.com": "Cognizant",
    "ibm.com": "IBM",
    "capgemini.com": "Capgemini",
    "reliance.com": "Reliance Industries",
    "jio.com": "Reliance Jio",
    "flipkart.com": "Flipkart",
    "paytm.com": "Paytm",
    "swiggy.in": "Swiggy",
    "zomato.com": "Zomato"
}

FREE_EMAIL_DOMAINS = {
    "gmail.com", "yahoo.com", "yahoo.co.in", "outlook.com", 
    "hotmail.com", "rediffmail.com", "icloud.com", "yandex.com",
    "protonmail.com", "proton.me", "gmx.com", "mail.com"
}

KNOWN_ATS_DOMAINS = {
    "greenhouse.io": "Greenhouse ATS",
    "lever.co": "Lever ATS",
    "myworkday.com": "Workday ATS",
    "ashbyhq.com": "Ashby ATS",
    "smartrecruiters.com": "SmartRecruiters ATS",
    "workable.com": "Workable ATS",
    "bamboohr.com": "BambooHR ATS",
    "icims.com": "iCIMS ATS",
    "jobvite.com": "Jobvite ATS",
    "taleo.net": "Oracle Taleo ATS"
}

THIRD_PARTY_FORM_DOMAINS = {
    "forms.gle", "docs.google.com", "typeform.com", "jotform.com", 
    "surveymonkey.com", "airtable.com"
}

def calculate_levenshtein_distance(s1: str, s2: str) -> int:
    """Pure Python Levenshtein distance calculation."""
    if len(s1) < len(s2):
        return calculate_levenshtein_distance(s2, s1)
    if len(s2) == 0:
        return len(s1)

    previous_row = range(len(s2) + 1)
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

def extract_domain_from_url(url_or_email: str) -> str:
    """Extract clean domain name from URL or email string."""
    cleaned = url_or_email.strip().lower()
    if "@" in cleaned:
        cleaned = cleaned.split("@")[-1]
    if not cleaned.startswith(("http://", "https://")):
        cleaned = "http://" + cleaned
    try:
        parsed = urlparse(cleaned)
        netloc = parsed.netloc or parsed.path
        netloc = netloc.split(":")[0]
        if netloc.startswith("www."):
            netloc = netloc[4:]
        return netloc
    except Exception:
        return ""

def check_disposable_or_free_email(email_or_domain: str, context_text: str = "") -> Optional[Dict[str, Any]]:
    domain = extract_domain_from_url(email_or_domain)
    if not domain:
        return None

    if domain in FREE_EMAIL_DOMAINS:
        claims_corp = any(kw in context_text.lower() for kw in [
            "tcs", "infosys", "wipro", "accenture", "amazon", "google", 
            "microsoft", "hcl", "tech mahindra", "cognizant", "ibm", "capgemini",
            "hr department", "hiring manager", "official offer letter", "corporate recruiter"
        ])
        
        return {
            "is_free_domain": True,
            "domain": domain,
            "claims_corporate": claims_corp,
            "title": f"Free Email Provider Used (@{domain})",
            "desc": f"Recruiter communicates via public free email (@{domain}) rather than an official company email domain." +
                    (" Corporate impersonation suspected!" if claims_corp else ""),
            "severity": "high" if claims_corp else "medium",
            "scam_type": "fee_scam"
        }
    return None

def check_ats_domain(url_or_domain: str, db: Session = None) -> Dict[str, Any]:
    """Check if the apply link belongs to a verified ATS domain or third-party form."""
    domain = extract_domain_from_url(url_or_domain)
    if not domain:
        return {"is_ats": False, "is_third_party_form": False}

    ats_map = dict(KNOWN_ATS_DOMAINS)
    if db:
        try:
            db_ats = db.query(ATSDomain).filter(ATSDomain.is_verified == True).all()
            for a in db_ats:
                ats_map[a.domain.lower()] = a.ats_name
        except Exception:
            pass

    # Exact or sub-domain ATS check (e.g. company.greenhouse.io)
    for ats_dom, ats_name in ats_map.items():
        if domain == ats_dom or domain.endswith("." + ats_dom):
            return {
                "is_ats": True,
                "domain": domain,
                "ats_name": ats_name,
                "title": f"Verified ATS Portal ({ats_name})",
                "desc": f"Application link uses verified enterprise ATS system: {ats_name}.",
                "severity": "info"
            }

    # Third-party form check (Google Form, Typeform, etc.)
    for form_dom in THIRD_PARTY_FORM_DOMAINS:
        if domain == form_dom or domain.endswith("." + form_dom):
            return {
                "is_ats": False,
                "is_third_party_form": True,
                "domain": domain,
                "title": f"Unverified Public Form Used ({domain})",
                "desc": f"Application link routes to a third-party form ({domain}) instead of an official careers portal or ATS. High data harvesting risk!",
                "severity": "high",
                "scam_type": "ghost_listing"
            }

    return {"is_ats": False, "is_third_party_form": False, "domain": domain}

def check_typosquatting(domain: str, db: Session = None) -> Optional[Dict[str, Any]]:
    if not domain or domain in FREE_EMAIL_DOMAINS or any(domain.endswith(ats) for ats in KNOWN_ATS_DOMAINS):
        return None

    legit_map = dict(SEED_LEGIT_DOMAINS)
    if db:
        try:
            db_domains = db.query(KnownDomain).filter(KnownDomain.is_verified_legitimate == True).all()
            for d in db_domains:
                legit_map[d.domain.lower()] = d.company_name
        except Exception:
            pass

    if domain in legit_map:
        return {
            "is_verified": True,
            "company_name": legit_map[domain],
            "title": "Verified Official Corporate Domain",
            "desc": f"Domain {domain} belongs to verified official company: {legit_map[domain]}.",
            "severity": "info"
        }

    domain_base = domain.split(".")[0]
    
    for seed_domain, company_name in legit_map.items():
        seed_base = seed_domain.split(".")[0]
        dist = calculate_levenshtein_distance(domain_base, seed_base)
        is_sub_spoof = (seed_base in domain_base or domain_base in seed_base) and domain != seed_domain
        
        if (dist > 0 and dist <= 2) or is_sub_spoof:
            return {
                "is_typosquat": True,
                "target_company": company_name,
                "target_domain": seed_domain,
                "title": f"Potential Brand Impersonation / Typosquatting ({company_name})",
                "desc": f"Domain '{domain}' closely resembles official domain '{seed_domain}' for {company_name}. High risk of fake job portal/phishing!",
                "severity": "high",
                "scam_type": "fee_scam"
            }

    return None

def _whois_sync(domain: str) -> Dict[str, Any]:
    try:
        w = whois.whois(domain)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date:
            if isinstance(creation_date, str):
                try:
                    creation_date = datetime.datetime.strptime(creation_date, "%Y-%m-%d")
                except Exception:
                    creation_date = None

            if creation_date:
                age_days = (datetime.datetime.utcnow() - creation_date).days
                is_recent = age_days < 90
                return {
                    "success": True,
                    "domain": domain,
                    "creation_date": creation_date.strftime("%Y-%m-%d"),
                    "age_days": age_days,
                    "is_under_90_days": is_recent,
                    "registrar": w.registrar if hasattr(w, "registrar") else "Unknown",
                    "title": f"Domain Registered Recently ({age_days} days ago)" if is_recent else f"Domain Age: {age_days} days",
                    "desc": f"Domain {domain} was registered on {creation_date.strftime('%Y-%m-%d')} ({age_days} days ago). " +
                            ("Scam sites are frequently created on newly registered domains (<90 days old)." if is_recent else "Domain age is established."),
                    "severity": "high" if is_recent else "low",
                    "scam_type": "fee_scam" if is_recent else None
                }
        return {
            "success": False,
            "domain": domain,
            "message": "WHOIS created date unavailable or privacy protected."
        }
    except Exception as e:
        return {
            "success": False,
            "domain": domain,
            "error": str(e),
            "message": "WHOIS lookup timed out or domain not registered."
        }

async def check_whois_domain_age(domain: str) -> Dict[str, Any]:
    if not domain or domain in FREE_EMAIL_DOMAINS:
        return {"success": False, "message": "N/A for free email provider"}
    clean_dom = extract_domain_from_url(domain)
    if not clean_dom:
        return {"success": False, "message": "Invalid domain format"}
    return await asyncio.to_thread(_whois_sync, clean_dom)
