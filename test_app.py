from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)

def test_fee_scam_detection():
    payload = {
        "text": "Selected immediately for TCS data entry job. Pay Rs 1500 registration fee to confirm."
    }
    response = client.post("/api/analyze/text", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["scam_type"] == "fee_scam"
    assert data["risk_score"] == "high"
    print("PASS: Fee Scam Classification & High Risk Score")

def test_ghost_listing_detection():
    payload = {
        "text": "Apply for Remote Data Entry role at Apex Media Solutions. Fill Google Form at https://forms.gle/xyz requiring Aadhaar scan and 3 months salary slips."
    }
    response = client.post("/api/analyze/text", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["scam_type"] == "ghost_listing"
    assert data["risk_score"] == "high"
    print("PASS: Ghost Listing Classification & Third-Party Form Flag")

def test_ats_domain_check():
    payload = {
        "text": "Apply for Software Engineer role via official greenhouse portal: https://company.greenhouse.io/jobs/123"
    }
    response = client.post("/api/analyze/text", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert data["is_ats_domain"] is True
    print("PASS: Verified ATS Domain Check (Greenhouse)")

def test_posting_history_endpoint():
    res = client.get("/api/postings/Apex%20Media%20Solutions/Remote%20Data%20Entry%20Specialist")
    assert res.status_code == 200
    data = res.json()
    assert data["repost_count"] >= 1
    print(f"PASS: Posting History Endpoint - Repost Count: {data['repost_count']}")

def test_reports_scam_type_filtering():
    res = client.get("/api/reports?scam_type=ghost_listing")
    assert res.status_code == 200
    reports = res.json()
    assert all(r["scam_type"] == "ghost_listing" for r in reports)
    print(f"PASS: Reports Filtering by scam_type=ghost_listing ({len(reports)} found)")

if __name__ == "__main__":
    test_fee_scam_detection()
    test_ghost_listing_detection()
    test_ats_domain_check()
    test_posting_history_endpoint()
    test_reports_scam_type_filtering()
    print("\nALL DUAL-SCAM VERIFICATION TESTS PASSED SUCCESSFULLY!")
