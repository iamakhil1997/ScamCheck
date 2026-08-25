import datetime
from fastapi import APIRouter, Depends, HTTPException, Request, UploadFile, File, Form, Query
from sqlalchemy.orm import Session
from sqlalchemy import or_, desc, func
from typing import Optional, List, Dict, Any

from app.database import get_db
from app.models import ScamReport, CompanyTitlePosting
from app.schemas import (
    AnalyzeTextRequest, AnalyzeUrlRequest, ReportCreateRequest, 
    ReportResponse, AnalysisResult, PostingHistoryResponse
)
from app.services.scanner import scan_text_for_red_flags
from app.services.domain_checker import (
    extract_domain_from_url, 
    check_disposable_or_free_email, 
    check_typosquatting, 
    check_whois_domain_age,
    check_ats_domain
)
from app.services.crowdsource import (
    query_crowdsourced_matches, 
    track_or_update_company_posting, 
    hash_ip, 
    mask_phone_number
)
from app.services.llm_analyzer import analyze_with_llm, merge_rule_and_llm_signals
from app.services.url_fetcher import fetch_url_text_and_domain
from app.services.ocr_service import extract_text_from_image_bytes

router = APIRouter(prefix="/api", tags=["API Endpoints"])

async def run_analysis_pipeline(
    text: str, 
    target_url_or_domain: Optional[str] = None, 
    user_company: Optional[str] = None,
    user_title: Optional[str] = None,
    db: Session = None
) -> Dict[str, Any]:
    """Core multi-step detection pipeline supporting FEE_SCAM and GHOST_LISTING."""
    # 1. Rule Scanner
    rule_results = scan_text_for_red_flags(text, db=db)
    
    company_name = user_company or rule_results.get("detected_company")
    job_title = user_title or rule_results.get("detected_title")

    # 2. Extract potential domain/emails/phones
    extracted_domain = None
    if target_url_or_domain:
        extracted_domain = extract_domain_from_url(target_url_or_domain)
    elif rule_results.get("extracted_urls"):
        extracted_domain = extract_domain_from_url(rule_results["extracted_urls"][0])
    elif rule_results.get("extracted_emails"):
        extracted_domain = extract_domain_from_url(rule_results["extracted_emails"][0])

    extracted_phone = rule_results["extracted_phones"][0] if rule_results.get("extracted_phones") else None

    # 3. Domain & ATS Checks
    domain_check_flags = []
    whois_info = None
    ats_info = None

    if target_url_or_domain or rule_results.get("extracted_urls"):
        link_to_check = target_url_or_domain or rule_results["extracted_urls"][0]
        ats_info = check_ats_domain(link_to_check, db=db)

    if rule_results.get("extracted_emails"):
        for email in rule_results["extracted_emails"]:
            free_flag = check_disposable_or_free_email(email, context_text=text)
            if free_flag:
                domain_check_flags.append(free_flag)

    if extracted_domain:
        typosquat_flag = check_typosquatting(extracted_domain, db=db)
        if typosquat_flag:
            domain_check_flags.append(typosquat_flag)

        # WHOIS lookup (Async)
        whois_info = await check_whois_domain_age(extracted_domain)
        if whois_info.get("success") and whois_info.get("is_under_90_days"):
            domain_check_flags.append({
                "title": whois_info["title"],
                "desc": whois_info["desc"],
                "severity": "high",
                "scam_type": "fee_scam"
            })

    # 4. Crowdsourced Database Lookup & Posting Tracker
    crowdsource_info = query_crowdsourced_matches(
        db, 
        domain=extracted_domain, 
        phone=extracted_phone,
        company_name=company_name,
        job_title=job_title
    )

    posting_history = crowdsource_info.get("posting_history")

    # 5. LLM Analysis (Anthropic Claude API)
    llm_results = await analyze_with_llm(text)

    # 6. Merge Signals with Rule Overrides
    final_assessment = merge_rule_and_llm_signals(
        rule_results=rule_results,
        llm_results=llm_results,
        domain_results=domain_check_flags,
        crowdsource_results=crowdsource_info,
        ats_info=ats_info
    )

    return {
        "scam_type": final_assessment["scam_type"],
        "risk_score": final_assessment["risk_score"],
        "confidence": final_assessment["confidence"],
        "red_flags": final_assessment["red_flags"],
        "explanation": final_assessment["explanation"],
        "extracted_text": text,
        "detected_domain": extracted_domain,
        "detected_phone": extracted_phone,
        "detected_company": company_name,
        "detected_title": job_title,
        "apply_link_domain": extracted_domain,
        "is_ats_domain": ats_info.get("is_ats", False) if ats_info else False,
        "domain_checks": {
            "flags": domain_check_flags,
            "whois": whois_info,
            "ats": ats_info
        },
        "crowdsource_matches": crowdsource_info.get("matched_reports_count", 0),
        "posting_history": posting_history
    }

@router.post("/analyze/text", response_model=AnalysisResult)
async def analyze_text_endpoint(payload: AnalyzeTextRequest, db: Session = Depends(get_db)):
    if not payload.text.strip():
        raise HTTPException(status_code=400, detail="Text payload cannot be empty.")
    
    res = await run_analysis_pipeline(
        text=payload.text, 
        user_company=payload.company_name, 
        user_title=payload.job_title, 
        db=db
    )
    return res

@router.post("/analyze/url", response_model=AnalysisResult)
async def analyze_url_endpoint(payload: AnalyzeUrlRequest, db: Session = Depends(get_db)):
    if not payload.url.strip():
        raise HTTPException(status_code=400, detail="URL cannot be empty.")

    url_result = await fetch_url_text_and_domain(payload.url)
    res = await run_analysis_pipeline(
        text=url_result["extracted_text"], 
        target_url_or_domain=url_result.get("domain"), 
        db=db
    )
    return res

@router.post("/analyze/screenshot", response_model=AnalysisResult)
async def analyze_screenshot_endpoint(file: UploadFile = File(...), db: Session = Depends(get_db)):
    if not file.content_type.startswith("image/"):
        raise HTTPException(status_code=400, detail="Uploaded file must be an image (PNG, JPG, JPEG, WEBP).")

    contents = await file.read()
    ocr_res = extract_text_from_image_bytes(contents)

    if not ocr_res["success"]:
        raise HTTPException(status_code=422, detail=ocr_res["error"])

    res = await run_analysis_pipeline(text=ocr_res["extracted_text"], db=db)
    return res

@router.post("/report")
async def report_scam_endpoint(
    request: Request,
    payload: ReportCreateRequest,
    db: Session = Depends(get_db)
):
    client_ip = request.client.host if request.client else "127.0.0.1"
    ip_hash = hash_ip(client_ip)

    existing = db.query(ScamReport).filter(
        ScamReport.reporter_ip_hash == ip_hash,
        or_(
            ScamReport.domain == payload.domain,
            ScamReport.submitted_text == payload.submitted_text
        )
    ).first()

    if existing:
        return {
            "success": True,
            "message": "Thank you! You have already reported this item recently.",
            "report_id": existing.id
        }

    new_report = ScamReport(
        submitted_text=payload.submitted_text,
        domain=extract_domain_from_url(payload.domain) if payload.domain else None,
        phone_number=payload.phone_number,
        company_name_claimed=payload.company_name_claimed,
        job_title=payload.job_title,
        scam_type=payload.scam_type or "fee_scam",
        risk_score=payload.risk_score,
        red_flags=payload.red_flags,
        explanation=payload.explanation,
        reporter_ip_hash=ip_hash,
        upvotes=1,
        created_at=datetime.datetime.utcnow()
    )

    db.add(new_report)
    db.commit()
    db.refresh(new_report)

    # Track or update CompanyTitlePosting if company and title provided
    if payload.company_name_claimed and payload.job_title:
        track_or_update_company_posting(
            db, 
            company_name=payload.company_name_claimed, 
            job_title=payload.job_title,
            apply_link_domain=payload.domain,
            is_no_response=(payload.scam_type == "ghost_listing")
        )

    return {
        "success": True,
        "message": "Report submitted successfully to the community database!",
        "report_id": new_report.id
    }

@router.get("/postings/{company}/{title}", response_model=PostingHistoryResponse)
def get_posting_history(company: str, title: str, db: Session = Depends(get_db)):
    """Fetch repost history and days open for a company+title pair."""
    posting = db.query(CompanyTitlePosting).filter(
        func.lower(CompanyTitlePosting.company_name) == company.strip().lower(),
        func.lower(CompanyTitlePosting.job_title) == title.strip().lower()
    ).first()

    if not posting:
        raise HTTPException(status_code=404, detail="No posting history found for this company and title.")

    days_open = (datetime.datetime.utcnow() - posting.first_seen_date).days
    return PostingHistoryResponse(
        company_name=posting.company_name,
        job_title=posting.job_title,
        first_seen_date=posting.first_seen_date,
        last_seen_date=posting.last_seen_date,
        repost_count=posting.repost_count,
        no_response_report_count=posting.no_response_report_count,
        days_open=days_open
    )

@router.post("/reports/{report_id}/upvote")
def upvote_report(report_id: int, db: Session = Depends(get_db)):
    report = db.query(ScamReport).filter(ScamReport.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    report.upvotes += 1
    db.commit()
    db.refresh(report)
    return {"id": report.id, "upvotes": report.upvotes, "downvotes": report.downvotes}

@router.post("/reports/{report_id}/downvote")
def downvote_report(report_id: int, db: Session = Depends(get_db)):
    report = db.query(ScamReport).filter(ScamReport.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    report.downvotes += 1
    db.commit()
    db.refresh(report)
    return {"id": report.id, "upvotes": report.upvotes, "downvotes": report.downvotes}

@router.get("/reports", response_model=List[ReportResponse])
def get_reports(
    scam_type: Optional[str] = Query(None),
    skip: int = Query(0, ge=0),
    limit: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db)
):
    """Get paginated community reports, optionally filtered by scam_type."""
    query = db.query(ScamReport)
    if scam_type and scam_type != "all":
        query = query.filter(ScamReport.scam_type == scam_type)

    reports = query.order_by(desc(ScamReport.created_at)).offset(skip).limit(limit).all()
    for r in reports:
        if r.phone_number:
            r.phone_number = mask_phone_number(r.phone_number)
    return reports

@router.get("/reports/search", response_model=List[ReportResponse])
def search_reports(
    q: str = Query(..., min_length=1),
    scam_type: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    query_str = q.strip().lower()
    query = db.query(ScamReport).filter(
        or_(
            ScamReport.domain.ilike(f"%{query_str}%"),
            ScamReport.company_name_claimed.ilike(f"%{query_str}%"),
            ScamReport.job_title.ilike(f"%{query_str}%"),
            ScamReport.phone_number.ilike(f"%{query_str}%"),
            ScamReport.submitted_text.ilike(f"%{query_str}%")
        )
    )
    if scam_type and scam_type != "all":
        query = query.filter(ScamReport.scam_type == scam_type)

    reports = query.order_by(desc(ScamReport.created_at)).limit(50).all()

    for r in reports:
        if r.phone_number:
            r.phone_number = mask_phone_number(r.phone_number)
    return reports
