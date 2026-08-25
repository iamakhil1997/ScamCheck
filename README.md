# ScamCheck - AI Job Scam Detection Tool

**ScamCheck** is a web application designed to analyze job postings, recruiter communications, SMS messages, offer letters, and screenshots to detect employment scams and recruitment fraud.

Built with **FastAPI**, **SQLAlchemy ORM**, **Jinja2 + HTMX**, **Python-WHOIS**, **Pytesseract OCR**, and **Anthropic Claude LLM**.

---

## Key Features

1. **3-Tab Submission Interface**:
   - **Paste Message**: Direct text analysis against scam regex pattern rules and AI models.
   - **Paste URL**: Fetches live web page body text, title, and performs domain intelligence.
   - **Upload Screenshot**: Uses **Pytesseract OCR** to extract text from WhatsApp, Telegram, or offer letter screenshots in memory.

2. **Multi-Layer Analysis Pipeline**:
   - **Rule-Based Red Flag Scanner**: Matches regex patterns (registration fees, instant selection, Telegram task scams, Aadhaar requests).
   - **Domain & WHOIS Checks**: Detects free/disposable emails (@gmail.com recruiters), checks WHOIS domain registration age (<90 days old), and flags typosquatting against major corporate brands (TCS, Infosys, Wipro, Accenture, Amazon, etc.).
   - **Crowdsourced Database**: Cross-references submitted phone numbers, domains, or company names against community reports.
   - **Anthropic Claude AI**: Asynchronous structured JSON analysis (`claude-sonnet-4-6`).
   - **Hard Rule Override**: Heuristic rules automatically override AI outputs to "HIGH RISK" when critical red flags are detected.

3. **Results & Emergency Guidance**:
   - Color-coded risk badge (Green / Amber / Red) with confidence rating.
   - Bullet list of specific red flags.
   - **"What To Do Next"** box linking to the **Indian Cyber Fraud Helpline `1930`** and **`cybercrime.gov.in`**.

4. **Community Scam Database**:
   - Searchable table of reported scam numbers, domains, and impersonation names.
   - HTMX-powered Upvote ("I got this too") / Downvote buttons.

5. **Educational Red Flags Checklist**:
   - Comprehensive guide on upfront fees, instant selection, Telegram task scams, and document harvesting.

---

## Non-Functional & Security Safeguards

- **Rate Limiting**: Integrated via `slowapi` to prevent submission spam.
- **Privacy & In-Memory OCR**: Screenshot uploads are processed entirely in memory via Pillow + Tesseract and **never stored to disk or database**.
- **Data Anonymization**: Phone numbers are masked (e.g. `+91 98****1234`) and reporter IPs are hashed (`sha256 + salt`).
- **Disclaimers**: Mandatory legal disclaimer rendered on all result cards and page footers.

---

## Project Structure

```
TrustIQ/
├── app/
│   ├── main.py                # FastAPI initialization & rate limiter setup
│   ├── config.py              # Application configuration
│   ├── database.py            # SQLAlchemy database engine & SessionLocal
│   ├── models.py              # SQLAlchemy models (ScamReport, ScamPattern, KnownDomain)
│   ├── schemas.py             # Pydantic schemas
│   ├── services/
│   │   ├── scanner.py         # Rule-based scanner (regex / keywords)
│   │   ├── domain_checker.py  # Free email, WHOIS age (<90d), Levenshtein typosquatting
│   │   ├── crowdsource.py     # Database lookup, IP hashing & phone masking
│   │   ├── llm_analyzer.py    # Anthropic Claude API integration & signal merger
│   │   ├── url_fetcher.py     # Async HTTP text scraper (httpx + BeautifulSoup)
│   │   └── ocr_service.py     # In-memory screenshot OCR (pytesseract + Pillow)
│   ├── routers/
│   │   ├── api.py             # REST API endpoints
│   │   └── views.py           # Jinja2 views & HTMX handlers
│   ├── templates/             # Jinja2 HTML templates & HTMX partials
│   │   ├── base.html
│   │   ├── index.html
│   │   ├── community.html
│   │   ├── red_flags.html
│   │   ├── result.html
│   │   └── partials/
│   │       ├── result_card.html
│   │       ├── report_table.html
│   │       ├── vote_buttons.html
│   │       └── error_alert.html
│   └── static/
├── seed_data.py               # Database seeder script
├── requirements.txt           # Python dependencies
├── .env.example               # Environment variables template
└── README.md                  # Documentation
```

---

## Getting Started

### 1. Installation

Clone the repository and install the dependencies:

```bash
pip install -r requirements.txt
```

*(Optional)* Copy `.env.example` to `.env` and set your `ANTHROPIC_API_KEY`:

```bash
cp .env.example .env
```

### 2. Seed Database

Run the seeder script to populate initial scam patterns, corporate domains, and demo community reports:

```bash
python seed_data.py
```

### 3. Run Development Server

Launch the app locally using Uvicorn:

```bash
python -m uvicorn app.main:app --reload
```

Open your browser and navigate to: `http://127.0.0.1:8000`

---

## API Endpoints Overview

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST` | `/api/analyze/text` | Submit text payload for multi-layer analysis |
| `POST` | `/api/analyze/url` | Submit URL for webpage fetching & WHOIS check |
| `POST` | `/api/analyze/screenshot` | Upload image for in-memory OCR & analysis |
| `POST` | `/api/report` | Submit domain/phone/company to community database |
| `GET` | `/api/reports` | Get paginated community scam reports |
| `GET` | `/api/reports/search?q=` | Search reported scam database |
| `POST` | `/api/reports/{id}/upvote` | Upvote report credibility |
| `POST` | `/api/reports/{id}/downvote` | Downvote report credibility |

---

## Production Hardening Pass (TODOs)

For production deployment beyond MVP:

1. **PostgreSQL Migration**: Swap `sqlite:///./scamcheck.db` in `app/config.py` to PostgreSQL (`postgresql://user:pass@localhost:5432/scamcheck`).
2. **Authentication & Authorization**: Add OAuth2 / JWT authentication for admin access and report moderation.
3. **CAPTCHA Protection**: Integrate Cloudflare Turnstile or reCAPTCHA v3 on `/api/analyze/*` and `/api/report` endpoints to eliminate automated bot abuse.
4. **Moderation Queue**: Implement an admin approval status (`pending`, `approved`, `rejected`) on `ScamReport` before community display.
5. **Background Workers**: Move WHOIS and LLM API tasks to Celery / Redis queue for ultra-fast response times under heavy load.
