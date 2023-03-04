"""urls.py: Module solving task 1 predicting malicious urls"""
import re

INPUT_URLS_PATH     = "./data/urls/urls.in"
URLS_DATABASE_PATH  = "./data/urls/domains_database"
OUTPUT_URLS_PATH    = "./urls-predictions.out"
EXTENSIONS_PATH     = "./patterns/extensions"
PHISHING_PATH       = "./patterns/phishing"
PHISHING_TLDS_PATH  = "./patterns/tlds"
URLS_WHITELIST_PATH = "./patterns/whitelist"

IP_REGEX    = r"[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+"

MAX_HYPENS  = 3
MAX_DOTS    = 4
MAX_DIGITS  = 5

def check_blacklist(url: str) -> int:
    """Checks if an URL is blacklisted in a database"""
    # heuritic 1
    with open(URLS_DATABASE_PATH, "r", encoding="utf8") as bad_urls:
        for bad_url in bad_urls:
            if bad_url.strip() in url:
                return True
    return False

def check_whitelist(url: str) -> int:
    """Checks if an URL is whitelisted: search engines"""
    with open(URLS_WHITELIST_PATH, "r", encoding="utf8") as whitelisted_urls:
        for safe_url in whitelisted_urls:
            if re.search(safe_url.strip(), url):
                return True
    return False

def check_ip_address(url: str) -> int:
    """Checks if URL is an IP address"""
    if re.search(IP_REGEX, url):
        return True
    return False

def check_patterns(url: str, file_path: str) -> int:
    """Checks if URL matches a given phishing pattern"""
    with open(file_path, "r", encoding="utf8") as pattern_file:
        for pattern in pattern_file:
            if re.search(pattern.strip(), url):
                return True
    return False

def predict_url(url):
    """
    Function that predicts if URL is malicious or harmless.
    Return 1 if malicious
    Returns 0 if harmless
    """

    # check if the current URL is blacklisted
    if check_blacklist(url):
        return 1

    # checks if url belongs to popular search engines
    if check_whitelist(url):
        return 0

    # checks if url contains potentially malicious patterns
    if check_patterns(url, EXTENSIONS_PATH) or \
        check_patterns(url, PHISHING_PATH) or \
        check_patterns(url, PHISHING_TLDS_PATH) or \
        check_ip_address(url) :
        return 1

    # breaks the string when finds the TLD
    tld = re.search(r"\.[a-z]+(:|/|$)", url)
    if tld:
        result = url.split(tld.group())

        # counts the number of digits - heuristic 6
        # counts the number of hypens - heuristic 7
        # counts the number of dots - heuristic 8
        if sum([char.isdigit() for char in result[0]]) >= MAX_DIGITS or \
            sum([1 if char == '-' else 0 for char in result[0]]) >= MAX_HYPENS or \
            sum([1 if char == '.' else 0 for char in result[0]]) >= MAX_DOTS:
            return 1

        # if domain is too short
        if len(result[0]) == 1:
            return 1

        # URL does not end in / - heuristic 9
        if '/' not in tld.group() and result[1] == '':
            return 1
    return 0
