from app.database import engine, Base, SessionLocal
from app.models import ScamPattern, KnownDomain, ScamReport, ATSDomain, CompanyTitlePosting
import datetime

def seed_database():
    Base.metadata.create_all(bind=engine)
    db = SessionLocal()

    try:
        # Seed ATSDomains if empty
        if db.query(ATSDomain).count() == 0:
            ats_entries = [
                ATSDomain(domain="greenhouse.io", ats_name="Greenhouse", is_verified=True),
                ATSDomain(domain="lever.co", ats_name="Lever", is_verified=True),
                ATSDomain(domain="myworkday.com", ats_name="Workday", is_verified=True),
                ATSDomain(domain="ashbyhq.com", ats_name="Ashby", is_verified=True),
                ATSDomain(domain="smartrecruiters.com", ats_name="SmartRecruiters", is_verified=True),
                ATSDomain(domain="workable.com", ats_name="Workable", is_verified=True),
                ATSDomain(domain="bamboohr.com", ats_name="BambooHR", is_verified=True)
            ]
            db.add_all(ats_entries)
            print("Seeded ATSDomains.")

        # Seed ScamPatterns if empty
        if db.query(ScamPattern).count() == 0:
            patterns = [
                ScamPattern(pattern_text=r"registration\s+fee", pattern_type="regex", scam_type="fee_scam", severity_weight="high", category="Upfront Fee"),
                ScamPattern(pattern_text=r"security\s+deposit", pattern_type="regex", scam_type="fee_scam", severity_weight="high", category="Upfront Fee"),
                ScamPattern(pattern_text=r"processing\s+fee", pattern_type="regex", scam_type="fee_scam", severity_weight="high", category="Upfront Fee"),
                ScamPattern(pattern_text=r"send\s+(your\s+)?aadhaar|send\s+pan\s+card", pattern_type="regex", scam_type="fee_scam", severity_weight="high", category="Document Harvesting"),
                ScamPattern(pattern_text=r"no\s+interview\s+required|direct\s+selection", pattern_type="regex", scam_type="fee_scam", severity_weight="high", category="Instant Selection"),
                ScamPattern(pattern_text=r"telegram\s+(hr|task|group)", pattern_type="regex", scam_type="fee_scam", severity_weight="high", category="Telegram Scam"),
                ScamPattern(pattern_text=r"forms\.gle|docs\.google\.com/forms|typeform\.com", pattern_type="regex", scam_type="ghost_listing", severity_weight="high", category="Off-Platform Form"),
                ScamPattern(pattern_text=r"previous\s+salary\s+slip|last\s+3\s+months\s+bank\s+statement", pattern_type="regex", scam_type="ghost_listing", severity_weight="high", category="Data Harvesting"),
                ScamPattern(pattern_text=r"continuous\s+recruitment|always\s+hiring", pattern_type="regex", scam_type="ghost_listing", severity_weight="medium", category="Ghost Pipeline")
            ]
            db.add_all(patterns)
            print("Seeded ScamPatterns.")

        # Seed KnownDomains if empty
        if db.query(KnownDomain).count() == 0:
            known_domains = [
                KnownDomain(domain="tcs.com", company_name="Tata Consultancy Services", is_verified_legitimate=True),
                KnownDomain(domain="infosys.com", company_name="Infosys", is_verified_legitimate=True),
                KnownDomain(domain="wipro.com", company_name="Wipro", is_verified_legitimate=True),
                KnownDomain(domain="accenture.com", company_name="Accenture", is_verified_legitimate=True),
                KnownDomain(domain="amazon.in", company_name="Amazon India", is_verified_legitimate=True),
                KnownDomain(domain="google.com", company_name="Google", is_verified_legitimate=True),
                KnownDomain(domain="microsoft.com", company_name="Microsoft", is_verified_legitimate=True)
            ]
            db.add_all(known_domains)
            print("Seeded KnownDomains.")

        # Seed sample CompanyTitlePosting tracking
        if db.query(CompanyTitlePosting).count() == 0:
            postings = [
                CompanyTitlePosting(
                    company_name="Apex Media Solutions",
                    job_title="Remote Data Entry Specialist",
                    apply_link_domain="forms.gle",
                    first_seen_date=datetime.datetime.utcnow() - datetime.timedelta(days=120),
                    last_seen_date=datetime.datetime.utcnow() - datetime.timedelta(days=2),
                    repost_count=5,
                    no_response_report_count=8
                ),
                CompanyTitlePosting(
                    company_name="Global Tech Hiring",
                    job_title="Junior Content Reviewer",
                    apply_link_domain="typeform.com",
                    first_seen_date=datetime.datetime.utcnow() - datetime.timedelta(days=90),
                    last_seen_date=datetime.datetime.utcnow() - datetime.timedelta(days=5),
                    repost_count=4,
                    no_response_report_count=3
                )
            ]
            db.add_all(postings)

        # Seed sample ScamReports
        if db.query(ScamReport).count() == 0:
            sample_reports = [
                ScamReport(
                    submitted_text="Received WhatsApp message asking for Rs 2500 security deposit for TCS work from home data entry job.",
                    domain="tcs-careers-india.online",
                    phone_number="+91 9876543210",
                    company_name_claimed="TCS Impersonator",
                    job_title="WFH Data Entry Operator",
                    scam_type="fee_scam",
                    risk_score="high",
                    confidence=95,
                    red_flags=["Security deposit demanded", "Typosquatting domain", "WhatsApp recruitment"],
                    explanation="Demanded money for TCS joining kit via fake domain tcs-careers-india.online.",
                    reporter_ip_hash="demo_hash_1",
                    upvotes=14,
                    downvotes=1,
                    created_at=datetime.datetime.utcnow() - datetime.timedelta(days=2)
                ),
                ScamReport(
                    submitted_text="Job posting for Remote Data Entry Specialist at Apex Media Solutions asks to apply via Google Form requiring full address, Aadhaar scan, and 3 months bank statements before any interview.",
                    domain="forms.gle",
                    company_name_claimed="Apex Media Solutions",
                    job_title="Remote Data Entry Specialist",
                    scam_type="ghost_listing",
                    risk_score="high",
                    confidence=92,
                    red_flags=["Google Form apply link used", "Disproportionate pre-interview data request", "Posting open >120 days"],
                    explanation="Ghost listing created to harvest applicant resumes and sensitive financial documents via Google Forms.",
                    reporter_ip_hash="demo_hash_2",
                    upvotes=19,
                    downvotes=0,
                    created_at=datetime.datetime.utcnow() - datetime.timedelta(days=4)
                )
            ]
            db.add_all(sample_reports)

        db.commit()
        print("Database seeding completed successfully.")
    except Exception as e:
        db.rollback()
        print(f"Error seeding database: {e}")
    finally:
        db.close()

if __name__ == "__main__":
    seed_database()
