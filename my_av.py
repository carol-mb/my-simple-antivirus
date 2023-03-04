#!/usr/bin/python3
"""Main module of homework solving task 1 and task 2"""

import csv
from urls import predict_url, OUTPUT_URLS_PATH, INPUT_URLS_PATH
from traffic import predict_traffic, OUTPUT_TRAFFIC_PATH, INPUT_TRAFFIC_PATH

def check_urls(input_file_path, output_file_path):
    """Solving task 1"""
    # reads data from the input file and opens the output file for writing
    with open(input_file_path, "r", encoding="utf8") as urls, \
        open(output_file_path, "w", encoding="utf8") as output_file:
        for url in urls:
            # removes the trailing newline
            url = url.strip().lower()

            # gets the prediction
            prediction = predict_url(url)

            # writes the result in the output file
            output_file.write(f"{prediction}\n")

def check_traffic(input_file_path, output_file_path):
    """Solving task 2"""
    # reads data from the input file and opens the output file for writing
    with open(input_file_path, "r", encoding="utf8") as traffic, \
        open(output_file_path, "w", encoding="utf8") as output_file:
        csv_reader = csv.reader(traffic, delimiter=',')
        next(csv_reader) # gets rid of the first row of csv file
        for traffic in csv_reader:
            # writes the result in the output file
            output_file.write(f"{predict_traffic(traffic)}\n")


def main():
    """Main function to be called when file runs as script"""
    check_urls(INPUT_URLS_PATH, OUTPUT_URLS_PATH)
    check_traffic(INPUT_TRAFFIC_PATH, OUTPUT_TRAFFIC_PATH)

if __name__ == "__main__":
    main()
    