import feeds.phishdirectory as phishdir
import feeds.urlhaus as urlhaus
import os
import asyncio # we need this to run our periodic scanning
from pathlib import Path
from fastapi import FastAPI
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
