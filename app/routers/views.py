import os
from fastapi import APIRouter, Depends, Request, Form, UploadFile, File, HTTPException, Query
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session
from sqlalchemy import or_, desc
from typing import Optional

from app.database import get_db
from app.models import ScamReport
from app.routers.api import run_analysis_pipeline
from app.services.url_fetcher import fetch_url_text_and_domain
from app.services.ocr_service import extract_text_from_image_bytes
from app.services.crowdsource import mask_phone_number

router = APIRouter(tags=["HTML Views"])

# Absolute path resolution for Vercel Serverless environment
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
templates_dir = os.path.join(BASE_DIR, "app", "templates")
templates = Jinja2Templates(directory=templates_dir)

@router.get("/", response_class=HTMLResponse)
def index_page(request: Request):
    return templates.TemplateResponse("index.html", {"request": request, "active_page": "home"})

@router.post("/analyze-htmx/text", response_class=HTMLResponse)
async def analyze_text_htmx(
    request: Request,
    job_text: str = Form(...),
    job_title: Optional[str] = Form(None),
    company_name: Optional[str] = Form(None),
    db: Session = Depends(get_db)
):
    if not job_text.strip():
        return templates.TemplateResponse(
            "partials/error_alert.html",
            {"request": request, "message": "Please enter or paste job text to analyze."}
        )

    res = await run_analysis_pipeline(
        text=job_text,
        user_company=company_name,
        user_title=job_title,
        db=db
    )
    return templates.TemplateResponse(
        "partials/result_card.html",
        {"request": request, "result": res}
    )

@router.post("/analyze-htmx/url", response_class=HTMLResponse)
async def analyze_url_htmx(
    request: Request,
    job_url: str = Form(...),
    db: Session = Depends(get_db)
):
    if not job_url.strip():
        return templates.TemplateResponse(
            "partials/error_alert.html",
            {"request": request, "message": "Please enter a valid job portal URL."}
        )

    url_res = await fetch_url_text_and_domain(job_url)
    res = await run_analysis_pipeline(
        text=url_res["extracted_text"],
        target_url_or_domain=url_res.get("domain"),
        db=db
    )
    return templates.TemplateResponse(
        "partials/result_card.html",
        {"request": request, "result": res}
    )

@router.post("/analyze-htmx/screenshot", response_class=HTMLResponse)
async def analyze_screenshot_htmx(
    request: Request,
    screenshot: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    if not screenshot.content_type.startswith("image/"):
        return templates.TemplateResponse(
            "partials/error_alert.html",
            {"request": request, "message": "Invalid file type. Please upload an image file (PNG, JPG, WEBP)."}
        )

    bytes_data = await screenshot.read()
    ocr_res = extract_text_from_image_bytes(bytes_data)

    if not ocr_res["success"]:
        return templates.TemplateResponse(
            "partials/error_alert.html",
            {"request": request, "message": ocr_res["error"]}
        )

    res = await run_analysis_pipeline(text=ocr_res["extracted_text"], db=db)
    return templates.TemplateResponse(
        "partials/result_card.html",
        {"request": request, "result": res}
    )

@router.get("/community", response_class=HTMLResponse)
def community_page(request: Request, db: Session = Depends(get_db)):
    reports = db.query(ScamReport).order_by(desc(ScamReport.created_at)).limit(20).all()
    for r in reports:
        if r.phone_number:
            r.phone_number = mask_phone_number(r.phone_number)
    return templates.TemplateResponse(
        "community.html",
        {"request": request, "reports": reports, "active_page": "community"}
    )

@router.get("/community/table-partial", response_class=HTMLResponse)
def community_table_partial(
    request: Request,
    q: Optional[str] = None,
    scam_type: Optional[str] = Query(None),
    db: Session = Depends(get_db)
):
    query_builder = db.query(ScamReport)
    if scam_type and scam_type != "all":
        query_builder = query_builder.filter(ScamReport.scam_type == scam_type)

    if q and q.strip():
        search_term = f"%{q.strip().lower()}%"
        query_builder = query_builder.filter(
            or_(
                ScamReport.domain.ilike(search_term),
                ScamReport.company_name_claimed.ilike(search_term),
                ScamReport.job_title.ilike(search_term),
                ScamReport.phone_number.ilike(search_term),
                ScamReport.submitted_text.ilike(search_term)
            )
        )
    reports = query_builder.order_by(desc(ScamReport.created_at)).limit(50).all()
    for r in reports:
        if r.phone_number:
            r.phone_number = mask_phone_number(r.phone_number)

    return templates.TemplateResponse(
        "partials/report_table.html",
        {"request": request, "reports": reports}
    )

@router.post("/community/{report_id}/vote-htmx", response_class=HTMLResponse)
def vote_htmx(
    request: Request,
    report_id: int,
    vote: str = Form(...),
    db: Session = Depends(get_db)
):
    report = db.query(ScamReport).filter(ScamReport.id == report_id).first()
    if report:
        if vote == "upvote":
            report.upvotes += 1
        elif vote == "downvote":
            report.downvotes += 1
        db.commit()
        db.refresh(report)

    return templates.TemplateResponse(
        "partials/vote_buttons.html",
        {"request": request, "report": report}
    )

@router.get("/red-flags", response_class=HTMLResponse)
def red_flags_page(request: Request):
    return templates.TemplateResponse("red_flags.html", {"request": request, "active_page": "red_flags"})

@router.get("/result/{report_id}", response_class=HTMLResponse)
def result_detail_page(request: Request, report_id: int, db: Session = Depends(get_db)):
    report = db.query(ScamReport).filter(ScamReport.id == report_id).first()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    
    if report.phone_number:
        report.phone_number = mask_phone_number(report.phone_number)

    return templates.TemplateResponse("result.html", {"request": request, "report": report})
