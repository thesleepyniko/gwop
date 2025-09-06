import feeds.phishdirectory as phishdir
import feeds.urlhaus as urlhaus
import asyncio # we need this to run our periodic scanning
from pathlib import Path
from fastapi import FastAPI

app = FastAPI()

DATA_DIR=Path("./data")

def refresh_feeds():
    # first, refreshing urlhaus
    urlhaus.refresh_local_cache()
    
    pass
    

if __name__ == "__main__":
    Path.mkdir(DATA_DIR, exist_ok=True, parents=True)
    refresh_feeds()