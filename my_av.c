#include <stdio.h>
#include "urls.h"
#include "traffic.h"

// transforms string to lowercase
void string_to_lower(char *string)
{
	int size = strlen(string);
	for (int i = 0; i < size; ++i)
		string[i] = tolower(string[i]);
}

int main(void)
{
	FILE *input_urls = fopen(INPUT_URLS_PATH, "r");
	FILE *output_urls = fopen(OUTPUT_URLS_PATH, "w");

	char input[1024];

	if (input_urls) {
		while (fgets(input, sizeof(input), input_urls)) {
			// remove trailing \n (newline)
			input[strlen(input) - 1] = '\0';

			// make the input lowercase
			string_to_lower(input);

			// print the output based on the prediction
			fprintf(output_urls, "%d\n", predict_url(input));
		}
		// close the input file
		fclose(input_urls);
	}

    // close the output file
	if (output_urls)
		fclose(output_urls);

    // open the files
	FILE *input_traffic = fopen(INPUT_TRAFFIC_PATH, "r");
	FILE *output_traffic = fopen(OUTPUT_TRAFFIC_PATH, "w");

	if (input_traffic) {
		// get rid of the first line of csv file
		fgets(input, sizeof(input), input_traffic);

		// read the rest of the lines
		while (fgets(input, sizeof(input), input_traffic)) {
			// remove trailing \n (newline)
			input[strlen(input) - 1] = '\0';

			// print the output based on the prediction
			fprintf(output_traffic, "%d\n", predict_traffic(input));
		}
		fclose(input_traffic);
	}

    // close the output file
	if (output_traffic)
		fclose(output_traffic);

	return 0;
}
