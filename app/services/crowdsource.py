import hashlib
import datetime
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import or_, func, and_
from app.models import ScamReport, CompanyTitlePosting
from app.config import settings

def hash_ip(ip_address: str) -> str:
    """Hash IP address for privacy anonymization."""
    if not ip_address:
        return "unknown"
    return hashlib.sha256(f"{ip_address}_{settings.HASH_SALT}".encode('utf-8')).hexdigest()[:32]

def mask_phone_number(phone: str) -> str:
    """Mask phone number for privacy display, e.g. +91 98****1234."""
    if not phone:
        return ""
    digits = ''.join(filter(str.isdigit, phone))
    if len(digits) >= 10:
        return f"+91 {digits[:2]}****{digits[-4:]}"
    elif len(digits) > 4:
        return f"{digits[:2]}****{digits[-2:]}"
    return "****"

def track_or_update_company_posting(
    db: Session,
    company_name: str,
    job_title: str,
    apply_link_domain: Optional[str] = None,
    is_no_response: bool = False
) -> Dict[str, Any]:
    """Track company+title pair and increment repost / no-response counters."""
    if not company_name or not job_title:
        return {"tracked": False}

    clean_comp = company_name.strip().lower()
    clean_title = job_title.strip().lower()

    posting = db.query(CompanyTitlePosting).filter(
        func.lower(CompanyTitlePosting.company_name) == clean_comp,
        func.lower(CompanyTitlePosting.job_title) == clean_title
    ).first()

    now = datetime.datetime.utcnow()

    if posting:
        posting.repost_count += 1
        posting.last_seen_date = now
        if apply_link_domain:
            posting.apply_link_domain = apply_link_domain
        if is_no_response:
            posting.no_response_report_count += 1
        db.commit()
        db.refresh(posting)
    else:
        posting = CompanyTitlePosting(
            company_name=company_name.strip(),
            job_title=job_title.strip(),
            apply_link_domain=apply_link_domain,
            first_seen_date=now,
            last_seen_date=now,
            repost_count=1,
            no_response_report_count=1 if is_no_response else 0
        )
        db.add(posting)
        db.commit()
        db.refresh(posting)

    days_open = (now - posting.first_seen_date).days

    return {
        "tracked": True,
        "company_name": posting.company_name,
        "job_title": posting.job_title,
        "repost_count": posting.repost_count,
        "no_response_report_count": posting.no_response_report_count,
        "first_seen_date": posting.first_seen_date.strftime("%Y-%m-%d"),
        "last_seen_date": posting.last_seen_date.strftime("%Y-%m-%d"),
        "days_open": days_open,
        "is_frequently_reposted": posting.repost_count >= 3,
        "is_unusually_old": days_open > 60
    }

def query_crowdsourced_matches(
    db: Session, 
    domain: Optional[str] = None, 
    phone: Optional[str] = None, 
    company_name: Optional[str] = None,
    job_title: Optional[str] = None
) -> Dict[str, Any]:
    """Query crowdsourced database for matches by domain, phone, company, or job title."""
    filters = []
    
    if domain:
        clean_dom = domain.strip().lower()
        filters.append(ScamReport.domain.ilike(f"%{clean_dom}%"))
        
    if phone:
        clean_phone = ''.join(filter(str.isdigit, phone))
        if len(clean_phone) >= 6:
            filters.append(ScamReport.phone_number.ilike(f"%{clean_phone[-6:]}%"))
            
    if company_name and len(company_name.strip()) > 2:
        clean_company = company_name.strip().lower()
        filters.append(ScamReport.company_name_claimed.ilike(f"%{clean_company}%"))

    matches = []
    if filters:
        matches = db.query(ScamReport).filter(or_(*filters)).order_by(ScamReport.created_at.desc()).limit(10).all()
    
    total_count = len(matches)

    # Also query posting history if company and title are known
    posting_info = None
    if company_name and job_title:
        clean_comp = company_name.strip().lower()
        clean_title = job_title.strip().lower()
        posting = db.query(CompanyTitlePosting).filter(
            func.lower(CompanyTitlePosting.company_name) == clean_comp,
            func.lower(CompanyTitlePosting.job_title) == clean_title
        ).first()

        if posting:
            now = datetime.datetime.utcnow()
            days_open = (now - posting.first_seen_date).days
            posting_info = {
                "company_name": posting.company_name,
                "job_title": posting.job_title,
                "repost_count": posting.repost_count,
                "no_response_report_count": posting.no_response_report_count,
                "first_seen_date": posting.first_seen_date.strftime("%Y-%m-%d"),
                "days_open": days_open,
                "is_ghost_candidate": posting.repost_count >= 3 or days_open >= 60 or posting.no_response_report_count >= 2
            }
    
    res = {
        "matched_reports_count": total_count,
        "has_matches": total_count > 0,
        "matched_reports": [
            {
                "id": r.id,
                "domain": r.domain,
                "phone": mask_phone_number(r.phone_number) if r.phone_number else None,
                "company": r.company_name_claimed,
                "job_title": r.job_title,
                "scam_type": r.scam_type,
                "risk_score": r.risk_score,
                "created_at": r.created_at.strftime("%Y-%m-%d") if r.created_at else "",
                "upvotes": r.upvotes
            } for r in matches
        ],
        "posting_history": posting_info
    }

    if total_count > 0:
        res["title"] = f"Reported {total_count} Time(s) by Community"
        res["desc"] = f"This domain/phone/company has been flagged {total_count} time(s) by other job seekers."
        res["severity"] = "high" if total_count >= 2 else "medium"

    return res
