from typing import List, Optional, Any, Dict
from pydantic import BaseModel, Field
from datetime import datetime

class AnalyzeTextRequest(BaseModel):
    text: str = Field(..., min_length=1, max_length=15000, description="Job text or offer letter content to analyze")
    job_title: Optional[str] = None
    company_name: Optional[str] = None

class AnalyzeUrlRequest(BaseModel):
    url: str = Field(..., description="Job posting or suspicious portal URL")

class AnalysisResult(BaseModel):
    scam_type: str  # "fee_scam", "ghost_listing", "phishing_portal", "unclear", "likely_legitimate"
    risk_score: str  # "low", "medium", "high"
    confidence: int  # 0 to 100
    red_flags: List[Any]
    explanation: str
    extracted_text: str
    detected_domain: Optional[str] = None
    detected_phone: Optional[str] = None
    detected_company: Optional[str] = None
    detected_title: Optional[str] = None
    apply_link_domain: Optional[str] = None
    is_ats_domain: Optional[bool] = False
    domain_checks: Optional[Dict[str, Any]] = None
    crowdsource_matches: Optional[int] = 0
    posting_history: Optional[Dict[str, Any]] = None

class ReportCreateRequest(BaseModel):
    submitted_text: str
    domain: Optional[str] = None
    phone_number: Optional[str] = None
    company_name_claimed: Optional[str] = None
    job_title: Optional[str] = None
    scam_type: str = "fee_scam"
    risk_score: str = "high"
    red_flags: List[Any] = []
    explanation: Optional[str] = None

class ReportResponse(BaseModel):
    id: int
    submitted_text: str
    domain: Optional[str] = None
    phone_number: Optional[str] = None
    company_name_claimed: Optional[str] = None
    job_title: Optional[str] = None
    scam_type: str
    risk_score: str
    confidence: int
    red_flags: Optional[List[Any]] = None
    explanation: Optional[str] = None
    upvotes: int
    downvotes: int
    created_at: datetime

    class Config:
        from_attributes = True

class PostingHistoryResponse(BaseModel):
    company_name: str
    job_title: str
    first_seen_date: datetime
    last_seen_date: datetime
    repost_count: int
    no_response_report_count: int
    days_open: int

    class Config:
        from_attributes = True
