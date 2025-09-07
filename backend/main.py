import feeds.phishdirectory as phishdir
import feeds.urlhaus as urlhaus
import os
import asyncio # we need this to run our periodic scanning
from urllib.parse import urlparse
from pathlib import Path
from fastapi import FastAPI
from fastapi.exceptions import HTTPException
from dotenv import load_dotenv

load_dotenv()

app = FastAPI()

DATA_DIR=Path("./data")

async def refresh_feeds():
    while True:
        # first, refreshing urlhaus
        urlhaus.refresh_local_cache()
        await asyncio.sleep(300)

loop = asyncio.get_event_loop()
loop.run_until_complete(refresh_feeds())

@app.get("/check-url")
def check_url(url: str):
    parse_result = urlparse(url)
    if not parse_result.scheme and len(url.replace(".", "")) == len(url):
        return HTTPException(status_code=400, detail="Invalid URL: must use HTTP/HTTPS with valid host")
    elif not parse_result.scheme and len(url.replace(".", "")) != len(url):
        url = "http://" + url
        parse_result = urlparse(url)
    if parse_result.scheme not in {"http", "https"}:
        return HTTPException(status_code=400, detail="Invalid URL: must use HTTP/HTTPS with valid host")
    phishdir_resp=phishdir.check_url_phishdir(url, None)
    if phishdir_resp:
        return phishdir_resp
    urlhaus.refresh_local_cache()
    urlhaus_resp = urlhaus.check_url_urlhaus(url, os.environ["URLHAUS_API_KEY"])
    if urlhaus_resp:
        return urlhaus_resp
    