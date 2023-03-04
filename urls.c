#include "urls.h"

// check if url matches a given phishing pattern
static int check_patterns(char *url, char *file_path)
{
	FILE *pattern_file = fopen(file_path, "r");

	if (pattern_file) {
		regex_t pattern;

		char input[32];

		while (fgets(input, sizeof(input), pattern_file)) {
			// removing trailing \n (newline)
			input[strlen(input) - 1] = '\0';

			if (regcomp(&pattern, input, REG_EXTENDED) == 0) {
				if (regexec(&pattern, url, 0, NULL, REG_EXTENDED) == 0) {
					regfree(&pattern);
					fclose(pattern_file);
					return 1;
				}
				regfree(&pattern);  // frees the memory
			}
		}
		fclose(pattern_file);   // closes the file
	}
	return 0;
}

static int check_ip_address(char *url)
{
	regex_t pattern;

	if (regcomp(&pattern, IP_REGEX, REG_EXTENDED) == 0) {
		if (regexec(&pattern, url, 0, NULL, REG_EXTENDED) == 0) {
			regfree(&pattern);
			return 1;
		}
		regfree(&pattern);
	}
	return 0;
}

static int check_blacklist(char *url)
{
	FILE *bad_urls = fopen(URLS_DATABASE_PATH, "r");
	if (bad_urls) {
		char bad_url[128];

		// reads blacklisted URLs database
		while (fgets(bad_url, sizeof(bad_url), bad_urls)) {
			// removing trailing \n (newline)
			bad_url[strlen(bad_url) - 1] = '\0';
			// check if bad_url in url
			if (strstr(url, bad_url)) {
				fclose(bad_urls);   // close the file, prevents memory leak
				return 1;
			}
		}
		// close the file
		fclose(bad_urls);
	}
	return 0;
}

static int check_whitelist(char *url)
{
	FILE *whitelisted_urls = NULL;
	whitelisted_urls = fopen(URLS_WHITELIST_PATH, "r");
	char safe_url[128];

	if (whitelisted_urls) {
		regex_t pattern;

		// reads whitelisted URLs file
		while (fgets(safe_url, sizeof(safe_url), whitelisted_urls)) {
			safe_url[strlen(safe_url) - 1] = '\0';
			if (regcomp(&pattern, safe_url, REG_EXTENDED) == 0) {
				// removing trailing \n (newline)
				// check if safe_url in url
				if (regexec(&pattern, url, 0, NULL, REG_EXTENDED) == 0) {
					regfree(&pattern);
					// close the file, prevents memory leak
					fclose(whitelisted_urls);
					return 1;
				}
				regfree(&pattern);
			}
		}
		// close the file
		fclose(whitelisted_urls);
	}

	whitelisted_urls = fopen(URLS_WHITELIST_C_PATH, "r");
	// reads whitelisted URLs file
	if (whitelisted_urls) {
		while (fgets(safe_url, sizeof(safe_url), whitelisted_urls)) {
			safe_url[strlen(safe_url) - 1] = '\0';
			if (url - strstr(url, safe_url) == 0) {
				fclose(whitelisted_urls);
				return 0;
			}
		}
		fclose(whitelisted_urls);
	}

	return 0;
}

static int count_digits(char *url)
{
	int size = strlen(url);
	int digits = 0;
	for (int i = 0; i < size; ++i)
		if (isdigit(url[i]))
			digits++;

	return digits;
}

static int count_symbols(char *url, char symbol)
{
	int size = strlen(url);
	int symbols = 0;
	for (int i = 0; i < size; ++i)
		if (url[i] == symbol)
			symbols++;

	return symbols;
}

// predicts if a given url is malicious or harmless
// returns 1 if malicious
// returns 0 if harmless
int predict_url(char *url)
{
	// check if the current URL is blacklisted
	if (check_blacklist(url))
		return 1;

	if (check_whitelist(url))
		return 0;

    // checks if url contains potentially malicious patterns
	if (check_patterns(url, EXTENSIONS_PATH) ||
		check_patterns(url, PHISHING_PATH) ||
		check_patterns(url, PHISHING_TLDS_PATH) ||
		check_ip_address(url)) {
		return 1;
	}

	regex_t pattern;    // variabile for regex matching

    // breaks the string when finds the TLD
	if (regcomp(&pattern, "\\.[:a-z:]+(:|/|$)", REG_EXTENDED) == 0) {
		regmatch_t match;
		if (regexec(&pattern, url, 1, &match, REG_EXTENDED) == 0) {
			regfree(&pattern);
			// URL ends in char (not /) - heuristic 9
			if (isalpha(url[match.rm_eo - 1]))
				return 1;
			url[match.rm_so] = '\0';
			if (strlen(url) == 1)
				return 1;

			// counts the digits - heuristic 6
			int digits = count_digits(url);

			// counts the hypens - heuristic 7
			int hypens = count_symbols(url, '-');

			// counts the dots - heuristic 8
			int dots = count_symbols(url, '.');

			if (digits >= MAX_DIGITS ||
				dots >= MAX_DOTS ||
				hypens >= MAX_HYPENS)
				return 1;
		}
		regfree(&pattern);
	}

	return 0;
}
