# shodan-downloader

A robust Python 3 tool for reliably downloading and filtering large datasets from [Shodan](https://www.shodan.io/).

## Why use this tool?

- **Reliable:** Handles API errors and interruptions with automatic retries.
- **Customizable:** Download only the fields you need, in a simple delimited format.
- **Easy to use:** One command to fetch thousands of results, even when the official Shodan CLI fails.

## Quick Start

1. **Install dependencies:**
    ```bash
    pip install -r requirements.txt
    ```

2. **Set your Shodan API key:**
    - Copy `.env.example` to `.env` and fill in your key, or
    - Set the `SHODAN_API_KEY` environment variable (e.g. `export SHODAN_API_KEY=your_key_here`).

3. **Download results:**
    ```bash
    python -m shodan_downloader.cli search -q 'apache port:8080' -f ip_str/port -o results.txt
    ```

4. **Get IP location:**
    ```bash
    python -m shodan_downloader.cli ip-location 8.8.8.8
    ```