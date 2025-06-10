# tests/test_core.py

from shodan_downloader.core import filter_result

def test_filter_result_basic():
    # Simulate a Shodan API response
    result = {
        "matches": [
            {
                "ip_str": "1.2.3.4",
                "port": 80,
                "location": {"city": "Testville", "country_name": "Testland"},
            }
        ]
    }
    filter_str = "ip_str/port/location.city/location.country_name"
    lines = filter_result(result, filter_str)
    assert lines == ["1.2.3.4;80;Testville;Testland"]