"""Minimal Gemini API key connectivity check."""

import json
import os
import time
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


key = os.environ.get("GEMINI_API_KEY")
if not key:
    raise SystemExit("Set GEMINI_API_KEY before running this script.")

for attempt in range(3):
    request = Request(
        "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.6-flash:generateContent",
        data=json.dumps({"contents": [{"parts": [{"text": "Reply with: API key works"}]}]}).encode(),
        headers={"Content-Type": "application/json", "x-goog-api-key": key},
        method="POST",
    )
    try:
        with urlopen(request, timeout=30) as response:
            print(json.load(response)["candidates"][0]["content"]["parts"][0]["text"])
        break
    except HTTPError as error:
        if error.code == 503 and attempt < 2:
            time.sleep(2 ** attempt)
            continue
        print(f"Gemini API error {error.code}: {error.read().decode()}")
        break
    except URLError as error:
        print(f"Connection failed: {error.reason}")
        break
