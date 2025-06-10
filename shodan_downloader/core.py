import logging
import time
from typing import List, Optional, TextIO
import shodan
from .constants import DEFAULT_PAGE_SIZE, MAX_RETRIES, RETRY_DELAY_SECONDS
from .utils import get_shodan_api_key
import json
from tqdm import tqdm
import socket
import struct

def get_nested_value(d, path):
    parts = path.split('.')
    value = d
    for i, part in enumerate(parts):
        # If this is the last part and it's a common X.509 field, try both cases
        if i == len(parts) - 1 and part in {"cn", "c", "o", "ou", "l", "st"}:
            # Try lowercase first, then uppercase
            if isinstance(value, dict):
                if part in value:
                    value = value[part]
                elif part.upper() in value:
                    value = value[part.upper()]
                else:
                    return ''
            else:
                return ''
        else:
            if isinstance(value, dict) and part in value:
                value = value[part]
            else:
                return ''
    # Special case: convert integer IP to dotted-quad
    if path == "ip" and isinstance(value, int):
        try:
            return socket.inet_ntoa(struct.pack("!I", value))
        except Exception:
            return str(value)
    if isinstance(value, (list, dict)):
        return json.dumps(value, ensure_ascii=False)
    return value if value is not None else ''

def filter_result(result: dict, filter_str: str) -> List[List[str]]:
    """
    Filter a single Shodan result dictionary according to the filter string.
    Returns a list of lists (one per match, each a list of field values).
    """
    filter_list = filter_str.split('/')
    output_rows = []
    for r in result.get('matches', []):
        row = []
        for ft in filter_list:
            try:
                value = get_nested_value(r, ft)
                row.append(str(value))
            except Exception as e:
                logging.debug(f"Error extracting field '{ft}': {e}")
                row.append('')
        output_rows.append(row)
    return output_rows

def search_shodan(
    query: str,
    filter_str: str,
    output_file: TextIO,
    limit: Optional[int] = None,
    api_key: Optional[str] = None,
    output_format: str = "csv",
):
    """
    Search Shodan with the given query and write filtered results to output_file.
    Supports CSV and JSONL output formats.
    """
    if api_key is None:
        api_key = get_shodan_api_key()
    api = shodan.Shodan(api_key)
    # Get total number of results
    try:
        result_number = api.count(query)
        total = result_number.get('total', 0)
        logging.info(f"Search query: '{query}' has {total} results")
    except shodan.exception.APIError as e:
        logging.error(f"Shodan API error: {e}")
        raise

    if limit and limit > 0:
        total = min(limit, total)
    cnt = 0
    page = 1
    filter_list = filter_str.split('/')
    # Progress bar setup
    num_pages = (total + DEFAULT_PAGE_SIZE - 1) // DEFAULT_PAGE_SIZE
    use_progress = num_pages > 10
    pbar = tqdm(total=total, initial=cnt, disable=not use_progress, unit="results")
    wrote_header = False
    while cnt < total:
        try:
            remaining = total - cnt
            page_size = min(DEFAULT_PAGE_SIZE, remaining)
            result = api.search(query, page=page)
            rows = filter_result(result, filter_str)
            # Only write up to the limit if on the last page
            if cnt + len(rows) > total:
                rows = rows[:total - cnt]
            if output_format == "csv":
                if not wrote_header:
                    output_file.write(','.join(filter_list) + '\n')
                    wrote_header = True
                for row in rows:
                    output_file.write(','.join(row) + '\n')
            elif output_format == "jsonl":
                for row in rows:
                    obj = {field: value for field, value in zip(filter_list, row)}
                    output_file.write(json.dumps(obj) + '\n')
            cnt += len(rows)
            if use_progress:
                pbar.update(len(rows))
            logging.info(f"Downloaded {cnt}/{total}")
            page += 1
            check = 0
        except shodan.exception.APIError as e:
            check += 1
            if "rate limit" in str(e).lower():
                logging.warning("Rate limit hit. Backing off for 60 seconds...")
                time.sleep(60)
            elif check > MAX_RETRIES:
                logging.error(f"Exit after {MAX_RETRIES} retries. Last error: {e}")
                break
            else:
                logging.warning(f"Shodan API error: {e}. Retrying in {RETRY_DELAY_SECONDS} seconds...")
                time.sleep(RETRY_DELAY_SECONDS)
        except Exception as e:
            logging.error(f"Unexpected error: {e}")
            break
    if use_progress:
        pbar.close()
    logging.info("Done!")

def get_ip_location(ip: str, api_key: Optional[str] = None) -> dict:
    """
    Get location information for a given IP address using Shodan.
    Returns a dictionary with latitude, longitude, and Google Maps URL.
    """
    if api_key is None:
        api_key = get_shodan_api_key()
    api = shodan.Shodan(api_key)
    try:
        host = api.host(str(ip))
        latitude = host.get('latitude')
        longitude = host.get('longitude')
        return {
            "ip": ip,
            "latitude": latitude,
            "longitude": longitude,
            "google_maps": f"https://maps.google.com/?q={latitude},{longitude}" if latitude and longitude else None,
            "raw": host,
        }
    except shodan.exception.APIError as e:
        logging.error(f"Shodan API error: {e}")
        raise