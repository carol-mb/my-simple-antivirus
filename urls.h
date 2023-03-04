#pragma once

#include <stdio.h>      // for file handling
#include <regex.h>      // for regex matching
#include <string.h>     // for string specific functions
#include <ctype.h>      // for tolower(), isdigit()

// files needed by task 1
#define INPUT_URLS_PATH     "./data/urls/urls.in"
#define URLS_DATABASE_PATH  "./data/urls/domains_database"
#define OUTPUT_URLS_PATH    "./urls-predictions.out"

// patterns found to match malicious urls
#define PHISHING_PATH       "./patterns/phishing"
#define EXTENSIONS_PATH     "./patterns/extensions"
#define PHISHING_TLDS_PATH  "./patterns/tlds"
#define URLS_WHITELIST_PATH "./patterns/whitelist"
#define URLS_WHITELIST_C_PATH "./patterns/whitelist_c"
#define IP_REGEX            "[:0-9:]*\\.[:0-9:]*\\.[:0-9:]*\\.[:0-9:]*/"

#define MAX_HYPENS  3
#define MAX_DOTS    4
#define MAX_DIGITS  5

int predict_url(char *url);
