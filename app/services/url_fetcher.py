import httpx
from bs4 import BeautifulSoup
from urllib.parse import urlparse
from typing import Dict, Any

async def fetch_url_text_and_domain(url: str) -> Dict[str, Any]:
    """Fetch URL web page content and extract clean text and domain."""
    cleaned_url = url.strip()
    if not cleaned_url.startswith(("http://", "https://")):
        cleaned_url = "https://" + cleaned_url

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
    }

    try:
        parsed = urlparse(cleaned_url)
        domain = parsed.netloc.split(":")[0]
        if domain.startswith("www."):
            domain = domain[4:]

        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            resp = await client.get(cleaned_url, headers=headers)
            resp.raise_for_request()

        soup = BeautifulSoup(resp.text, "html.parser")

        # Remove script and style elements
        for script in soup(["script", "style", "nav", "footer", "header", "noscript"]):
            script.decompose()

        # Get text
        text = soup.get_text(separator=" ", strip=True)

        # Get page title
        title = soup.title.string.strip() if soup.title and soup.title.string else ""

        # Limit text length
        text_sample = text[:10000]

        return {
            "success": True,
            "url": cleaned_url,
            "domain": domain,
            "title": title,
            "extracted_text": f"Page Title: {title}\nDomain: {domain}\n\nPage Content:\n{text_sample}"
        }

    except Exception as e:
        # Fallback to analyzing the URL itself if fetching fails
        parsed = urlparse(cleaned_url)
        domain = parsed.netloc.split(":")[0]
        if domain.startswith("www."):
            domain = domain[4:]

        return {
            "success": False,
            "url": cleaned_url,
            "domain": domain,
            "error": str(e),
            "extracted_text": f"URL: {cleaned_url}\nDomain: {domain}\nNotice: Could not fetch live webpage body (Error: {str(e)}). Analyzing domain structure."
        }
