import argparse
import sys
import logging
from .core import search_shodan, get_ip_location
from .utils import setup_logging, get_shodan_api_key, get_cached_filters

def main():
    parser = argparse.ArgumentParser(
        description="ShodanDownloader: search, filter, and download Shodan results.",
        epilog="""
            Examples:
            shodan-downloader search -q 'ssl:"O=Fortinet Ltd., CN=FortiGate" country:IL' -f ip_str/port -o results.csv
            shodan-downloader search -q 'apache port:8080' -f ip_str/port -o results.jsonl -F jsonl
            shodan-downloader ip-location 8.8.8.8
        """
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", help="Enable verbose logging"
    )
    parser.add_argument(
        "--refresh-filters", action="store_true",
        help="Force refresh the Shodan filters list cache"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    # Subcommand: search
    search_parser = subparsers.add_parser(
        "search", help="Search Shodan and export filtered results"
    )
    search_parser.add_argument(
        "-q", "--query", type=str, required=True, help="Shodan search query string"
    )
    search_parser.add_argument(
        "-f", "--filter", type=str, required=True,
        help="Filter string (fields separated by '/'). Use --refresh-filters to update. Available fields are dynamically loaded."
    )
    search_parser.add_argument(
        "-o", "--output", type=str, required=True, help="Output file path"
    )
    search_parser.add_argument(
        "--limit", type=int, default=0, help="Limit number of results (default: all)"
    )
    search_parser.add_argument(
        "-F", "--format", type=str, choices=["csv", "jsonl"], default="csv",
        help="Output format: csv (default) or jsonl"
    )
    # Subcommand: ip-location
    ip_parser = subparsers.add_parser(
        "ip-location", help="Get location info for a specific IP"
    )
    ip_parser.add_argument(
        "ip", type=str, help="IP address to look up"
    )
    args = parser.parse_args()
    setup_logging(args.verbose)
    api_key = get_shodan_api_key()
    try:
        validate_shodan_api_key(api_key)
    except Exception as e:
        logging.error(str(e))
        sys.exit(1)
    # Fetch available filters, using refresh if requested
    available_filters = get_cached_filters(api_key, force_refresh=args.refresh_filters)
    if args.command == "search":
        requested_fields = args.filter.split('/')
        invalid_fields = [f for f in requested_fields if f not in available_filters]
        if invalid_fields:
            logging.error(f"Invalid filter field(s): {', '.join(invalid_fields)}")
            logging.info(f"Available fields: {', '.join(available_filters)}")
            sys.exit(1)
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                search_shodan(
                    query=args.query,
                    filter_str=args.filter,
                    output_file=f,
                    limit=args.limit if args.limit > 0 else None,
                    output_format=args.format,
                    api_key=api_key,
                )
        except Exception as e:
            logging.error(f"Error during search: {e}")
            sys.exit(1)
    elif args.command == "ip-location":
        try:
            info = get_ip_location(args.ip, api_key=api_key)
            print(f"IP: {info['ip']}")
            print(f"Latitude: {info['latitude']}")
            print(f"Longitude: {info['longitude']}")
            if info['google_maps']:
                print(f"Google Maps: {info['google_maps']}")
        except Exception as e:
            logging.error(f"Error during IP location lookup: {e}")
            sys.exit(1)
            
def validate_shodan_api_key(api_key):
    import shodan
    api = shodan.Shodan(api_key)
    try:
        api.info()
    except shodan.exception.APIError as e:
        raise RuntimeError(f"Invalid Shodan API key: {e}")

if __name__ == "__main__":
    main()