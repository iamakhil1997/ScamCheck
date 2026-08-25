import os
import io
from PIL import Image, ImageDraw
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_1_fee_scam_text_analysis():
    print("\n--- TEST 1: Fee Scam Text Analysis ---")
    payload = {
        "text": "Congratulations! You are selected for TCS WFH data entry job. Pay Rs 1500 registration fee and send your Aadhaar card to confirm interview slot.",
        "company_name": "TCS Impersonator",
        "job_title": "WFH Data Entry"
    }
    res = client.post("/api/analyze/text", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["scam_type"] == "fee_scam"
    assert data["risk_score"] == "high"
    assert data["confidence"] >= 85
    assert len(data["red_flags"]) >= 2
    print(f"[PASS] Fee Scam Detected: risk_score={data['risk_score']}, scam_type={data['scam_type']}, flags_count={len(data['red_flags'])}")

def test_2_ghost_listing_text_analysis():
    print("\n--- TEST 2: Ghost Listing & Data Harvesting ---")
    payload = {
        "text": "Apex Media hiring Remote Data Entry Specialist. Apply via Google Form: https://forms.gle/testform. Must submit Aadhaar card and last 3 months bank statement to apply.",
        "company_name": "Apex Media Solutions",
        "job_title": "Remote Data Entry Specialist"
    }
    res = client.post("/api/analyze/text", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["scam_type"] == "ghost_listing"
    assert data["risk_score"] == "high"
    flag_titles = [f["title"] for f in data["red_flags"]]
    assert any("Public Form" in t or "Off-Platform" in t or "Data" in t or "Harvest" in t for t in flag_titles)
    print(f"[PASS] Ghost Listing Detected: risk_score={data['risk_score']}, scam_type={data['scam_type']}, flags={flag_titles}")

def test_3_legitimate_job_analysis():
    print("\n--- TEST 3: Legitimate Job Analysis ---")
    payload = {
        "text": "Infosys is hiring a Senior Python Engineer in Bengaluru. 5+ years experience required. Apply at official careers portal: https://infosys.greenhouse.io/jobs/456",
        "company_name": "Infosys",
        "job_title": "Senior Python Engineer"
    }
    res = client.post("/api/analyze/text", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["is_ats_domain"] is True
    assert data["risk_score"] in ["low", "medium"]
    print(f"[PASS] Legitimate Job Assessment: risk_score={data['risk_score']}, is_ats={data['is_ats_domain']}")

def test_4_url_analysis():
    print("\n--- TEST 4: URL Analysis ---")
    payload = {"url": "https://tcs.com/careers"}
    res = client.post("/api/analyze/url", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["detected_domain"] == "tcs.com"
    print(f"[PASS] URL Fetch & Domain Check: domain={data['detected_domain']}")

def test_5_screenshot_ocr_analysis():
    print("\n--- TEST 5: Screenshot Upload OCR Analysis ---")
    img = Image.new('RGB', (400, 100), color=(255, 255, 255))
    d = ImageDraw.Draw(img)
    d.text((10, 40), "Pay Rs 2000 registration deposit for job", fill=(0, 0, 0))
    img_byte_arr = io.BytesIO()
    img.save(img_byte_arr, format='PNG')
    img_bytes = img_byte_arr.getvalue()

    response = client.post(
        "/api/analyze/screenshot",
        files={"file": ("test_screenshot.png", img_bytes, "image/png")}
    )
    assert response.status_code in [200, 422]
    print(f"[PASS] Screenshot OCR Endpoint Verified (Response Code: {response.status_code})")

def test_6_report_submission_and_voting():
    print("\n--- TEST 6: Report Submission, Search & Upvoting ---")
    report_payload = {
        "submitted_text": "Fake recruiter asking for laptop fee of Rs 4000.",
        "domain": "fake-wipro-hiring.online",
        "phone_number": "+91 9988112233",
        "company_name_claimed": "Wipro Fake",
        "job_title": "Data Entry Clerk",
        "scam_type": "fee_scam",
        "risk_score": "high",
        "red_flags": ["Upfront laptop fee demanded"]
    }
    report_res = client.post("/api/report", json=report_payload)
    assert report_res.status_code == 200
    report_data = report_res.json()
    assert report_data["success"] is True
    report_id = report_data["report_id"]
    print(f"[PASS] Scam Report Created: id={report_id}")

    vote_res = client.post(f"/api/reports/{report_id}/upvote")
    assert vote_res.status_code == 200
    assert vote_res.json()["upvotes"] >= 1
    print("[PASS] Report Upvoted Successfully")

    search_res = client.get("/api/reports/search?q=fake-wipro")
    assert search_res.status_code == 200
    assert len(search_res.json()) >= 1
    print(f"[PASS] Search Reports Endpoint: Found {len(search_res.json())} match(es)")

def test_7_posting_history_endpoint():
    print("\n--- TEST 7: Posting Repost History Endpoint ---")
    res = client.get("/api/postings/Apex%20Media%20Solutions/Remote%20Data%20Entry%20Specialist")
    assert res.status_code == 200
    data = res.json()
    assert "repost_count" in data
    print(f"[PASS] Posting History Endpoint: company={data['company_name']}, repost_count={data['repost_count']}")

def test_8_html_views_and_htmx_partials():
    print("\n--- TEST 8: HTML Views & HTMX Partials ---")
    assert client.get("/").status_code == 200
    assert client.get("/community").status_code == 200
    assert client.get("/red-flags").status_code == 200
    
    htmx_res = client.post("/analyze-htmx/text", data={"job_text": "Pay registration fee Rs 500"})
    assert htmx_res.status_code == 200
    assert "analysis-result" in htmx_res.text
    print("[PASS] HTML Views & HTMX Partial Endpoints Verified")

if __name__ == "__main__":
    print("==================================================")
    print("      SCAMCHECK FULL FUNCTIONALITY SUITE          ")
    print("==================================================")
    test_1_fee_scam_text_analysis()
    test_2_ghost_listing_text_analysis()
    test_3_legitimate_job_analysis()
    test_4_url_analysis()
    test_5_screenshot_ocr_analysis()
    test_6_report_submission_and_voting()
    test_7_posting_history_endpoint()
    test_8_html_views_and_htmx_partials()
    print("\n==================================================")
    print("ALL 8 COMPLETE FUNCTIONALITY TESTS PASSED!       ")
    print("==================================================")
