from urllib.parse import urlparse, unquote

def parse_url(url: str):
    url.strip()
    parsed = urlparse(url)

    if not parsed.scheme:
        parsed = urlparse(f"http://{url}") # if there isn't a scheme from the parsed we'll reparse with http:// put in front of it just in case

    # first parsing the scheme
    scheme = parsed.scheme.lower()

    # then we parse host + port
    host, sep, port = parsed.netloc.partition(":")
    host = host.lower().rstrip(".")

    # if there is a port we either strip it because it's default or add it onto the host
    if port:
        if (scheme == "http" and port == "80") or (scheme == "https" and port == "443"):
            netloc = host
        else:
            netloc = f"{host}:{port}"
    else:
        netloc = host

    path = parsed.path
    for _ in range(2):
        new_path = unquote(path)
        if new_path == path:
            break
        path = new_path

    # then we reconstruct the url
    url_parsed = f"{scheme}://{netloc}{parsed.path}"

    # finally we'll add the query and fragment back on
    if parsed.query:
        url_parsed += f"?{parsed.query}"
    if parsed.fragment:
        url_parsed += f"#{parsed.fragment}"
    
    return url_parsed