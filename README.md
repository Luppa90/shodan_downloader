# Shodan Downloader

A Python tool for downloading and filtering large datasets from Shodan.

## Installation

```bash
pip install shodan-downloader
```

## Usage

1. **Set your Shodan API key**

    ```bash
    export SHODAN_API_KEY=your_key_here
    ```

2. **Search and download results**

    ```bash
    shodan-downloader search -q 'apache port:8080' -f ip_str/port -o results.txt
    ```

3. **Get IP location**

    ```bash
    shodan-downloader ip-location 8.8.8.8
    ```