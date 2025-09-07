import feeds.phishdirectory as phishdir
import feeds.urlhaus as urlhaus
import os
import asyncio # we need this to run our periodic scanning
from urllib.parse import urlparse
from pathlib import Path
from fastapi import FastAPI
from fastapi.responses import JSONResponse
from fastapi.exceptions import HTTPException
import backend.resources.definitions as definitions
from typing import List
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

def construct_verdict(responses: List[definitions.UrlCheckResponse]):
    cleared_by_temp=[]
    flagged_by_temp=[]
    errored_by_temp=[]
    malicious_flag=False
    suspicious_flag=False
    if len(responses) == 0:
        raise ValueError("Must have at least 1 response!")
    elif len(responses) == 1:
        for response in responses:
            if not response.is_threat:
                cleared_by_temp.append(response.source)
            elif response.is_threat and response.error is None:
                flagged_by_temp.append(response.source)
            else:
                errored_by_temp.append(response.source)
        return definitions.ClientResponse(
            verdict=definitions.Verdict.malicious if responses[0].result == definitions.Result.hit else definitions.Verdict.clean,
            is_threat=True if responses[0].result == definitions.Result.hit else False,
            threat_type=responses[0].threat_type,
            confirmed_via=responses[0].via,
            flagged_by=flagged_by_temp,
            cleared_by=cleared_by_temp,
            errored_by=errored_by_temp,
            evidence=responses
        )
    elif len(responses) > 1:
        for response in responses:
            if not response.is_threat:
                cleared_by_temp.append(response.source)
            elif response.is_threat and response.error is None:
                flagged_by_temp.append(response.source)
            else:
                errored_by_temp.append(response.source)
        if len(flagged_by_temp) >= (len(cleared_by_temp) +  + len(errored_by_temp)):
            majority_flag=True
        elif len(flagged_by_temp) >= len(cleared_by_temp):
            malicious_flag=True # we want to ensure that if consensus is not reached due to errors, we call it suspicious
        elif len(cleared_by_temp) >= len(flagged_by_temp):
            malicious_flag = False
            suspicious_flag = False    
        if malicious_flag:
            ret_verdict = definitions.Verdict.malicious
        elif suspicious_flag:
            ret_verdict = definitions.Verdict.suspicious
        else:
            ret_verdict = definitions.Verdict.clean
        return definitions.ClientResponse( # TODO: Finish implementing
            verdict=ret_verdict,
            is_threat=True if ret_verdict in [definitions.Verdict.malicious, definitions.Verdict.suspicious] else False,
        )
        
        

@app.get("/check-url") # TODO: Aggregate from multiple and simple verdict if 50% agree min
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
    