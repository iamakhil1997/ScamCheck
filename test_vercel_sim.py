import os
import sys

# Simulate Vercel Serverless Environment
os.environ["VERCEL"] = "1"

from fastapi.testclient import TestClient
from app.main import app
from app.database import engine, Base
from seed_data import seed_database

# Ensure database tables and seed data are initialized on /tmp
Base.metadata.create_all(bind=engine)
seed_database()

client = TestClient(app)

def test_vercel_simulation():
    print("Testing Vercel Serverless Simulation...")
    
    # Test Home Page
    res_home = client.get("/")
    assert res_home.status_code == 200
    assert "Is That Job Offer Real Or A" in res_home.text
    print("PASS: Home Page Rendered on Serverless Simulation")

    # Test Text Analysis
    res_text = client.post("/api/analyze/text", json={"text": "Pay registration fee Rs 1000"})
    assert res_text.status_code == 200
    data = res_text.json()
    assert data["risk_score"] == "high"
    print("PASS: Text Analysis Endpoint on Serverless Simulation")

    # Test Community DB Page
    res_comm = client.get("/community")
    assert res_comm.status_code == 200
    assert "Community Scam & Ghost Database" in res_comm.text
    print("PASS: Community Page Rendered on Serverless Simulation")

    # Test Red Flags Page
    res_rf = client.get("/red-flags")
    assert res_rf.status_code == 200
    assert "Red Flags Checklist" in res_rf.text
    print("PASS: Red Flags Checklist Page Rendered on Serverless Simulation")

    print("\nALL VERCEL SIMULATION TESTS PASSED SUCCESSFULLY!")

if __name__ == "__main__":
    test_vercel_simulation()
