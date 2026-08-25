import datetime
from sqlalchemy import Column, Integer, String, Text, Boolean, DateTime, JSON
from app.database import Base

class ScamReport(Base):
    __tablename__ = "scam_reports"

    id = Column(Integer, primary_key=True, index=True)
    submitted_text = Column(Text, nullable=False)
    domain = Column(String(255), index=True, nullable=True)
    phone_number = Column(String(100), index=True, nullable=True)
    company_name_claimed = Column(String(255), index=True, nullable=True)
    job_title = Column(String(255), index=True, nullable=True)
    scam_type = Column(String(50), nullable=False, default="fee_scam")  # "fee_scam", "ghost_listing", "phishing_portal", "unclear", "likely_legitimate"
    risk_score = Column(String(50), nullable=False, default="medium")  # "low", "medium", "high"
    confidence = Column(Integer, default=70)  # 0 to 100
    red_flags = Column(JSON, nullable=True)  # List of red flag dicts
    explanation = Column(Text, nullable=True)
    reporter_ip_hash = Column(String(64), nullable=True)
    upvotes = Column(Integer, default=0)
    downvotes = Column(Integer, default=0)
    created_at = Column(DateTime, default=datetime.datetime.utcnow)

class CompanyTitlePosting(Base):
    __tablename__ = "company_title_postings"

    id = Column(Integer, primary_key=True, index=True)
    company_name = Column(String(255), nullable=False, index=True)
    job_title = Column(String(255), nullable=False, index=True)
    apply_link_domain = Column(String(255), nullable=True)
    first_seen_date = Column(DateTime, default=datetime.datetime.utcnow)
    last_seen_date = Column(DateTime, default=datetime.datetime.utcnow)
    repost_count = Column(Integer, default=1)
    no_response_report_count = Column(Integer, default=0)

class ScamPattern(Base):
    __tablename__ = "scam_patterns"

    id = Column(Integer, primary_key=True, index=True)
    pattern_text = Column(String(255), unique=True, nullable=False, index=True)
    pattern_type = Column(String(50), default="keyword")  # "keyword" or "regex"
    scam_type = Column(String(50), default="fee_scam")  # "fee_scam" or "ghost_listing"
    severity_weight = Column(String(50), default="high")  # "high", "medium", "low"
    category = Column(String(100), default="Financial Fee")

class KnownDomain(Base):
    __tablename__ = "known_domains"

    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String(255), unique=True, nullable=False, index=True)
    company_name = Column(String(255), nullable=False)
    is_verified_legitimate = Column(Boolean, default=True)

class ATSDomain(Base):
    __tablename__ = "ats_domains"

    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String(255), unique=True, nullable=False, index=True)
    ats_name = Column(String(255), nullable=False)
    is_verified = Column(Boolean, default=True)
