from urllib.parse import urlparse, unquote

def parse_url(url: str):
    url=url.strip()
    parsed = urlparse(url)


    if not parsed.scheme:
        if url.startswith("//"):
            parsed = urlparse(f"http:{url}") 
        else:
            parsed = urlparse(f"http://{url}") # if there isn't a scheme from the parsed we'll reparse with http:// put in front of it just in case

    # first parsing the scheme
    scheme = parsed.scheme.lower()

    # then we parse host + port
    if parsed.hostname:
        host = parsed.hostname.lower().rstrip(".")
    else:
        # no host found -> reject or raise error
        return None

    if not parsed.path:
        path = "/"
    else:
        path = parsed.path
    port = parsed.port

    # if there is a port we either strip it because it's default or add it onto the host
    if port:
        if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
            netloc = host
        else:
            netloc = f"{host}:{port}"
    else:
        netloc = host

    # then we reconstruct the url
    url_parsed = f"{scheme}://{netloc}{path}"

    # finally we'll add the query and fragment back on
    if parsed.query:
        url_parsed += f"?{parsed.query}"
    if parsed.fragment:
        url_parsed += f"#{parsed.fragment}"
    
    return url_parsed