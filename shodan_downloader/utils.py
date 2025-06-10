import os
import time
import json
import requests
import logging

FILTERS_CACHE_PATH = os.path.expanduser("~/.shodan_downloader_filters.json")
FILTERS_CACHE_TTL = 24 * 3600  # 24 hours

def fetch_shodan_filters(api_key):
    url = f"https://api.shodan.io/shodan/host/search/filters?key={api_key}"
    resp = requests.get(url)
    resp.raise_for_status()
    filters = resp.json()
    # The API returns a list of strings directly
    if not isinstance(filters, list):
        raise RuntimeError("Unexpected response format from Shodan filters API")
    return filters

def get_cached_filters(api_key, force_refresh=False):
    # Check cache
    if not force_refresh and os.path.exists(FILTERS_CACHE_PATH):
        mtime = os.path.getmtime(FILTERS_CACHE_PATH)
        if time.time() - mtime < FILTERS_CACHE_TTL:
            try:
                with open(FILTERS_CACHE_PATH, "r") as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError) as e:
                logging.warning(f"Filter cache corrupted or unreadable: {e}. Refreshing cache.")
    # Fetch and cache
    filters = fetch_shodan_filters(api_key)
    with open(FILTERS_CACHE_PATH, "w") as f:
        json.dump(filters, f)
    return filters

def get_shodan_api_key():
    """
    Retrieve the Shodan API key from the environment variable.
    Raises an exception if not found.
    """
    api_key = os.environ.get("SHODAN_API_KEY")
    if not api_key:
        raise RuntimeError(
            "Shodan API key not found. Please set SHODAN_API_KEY in your environment."
        )
    return api_key

def setup_logging(verbose: bool = False):
    """
    Set up logging for the application.
    """
    level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(asctime)s [%(levelname)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )