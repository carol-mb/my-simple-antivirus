#pragma once

#include <stdlib.h>     // for atof(), atoi()
#include <string.h>

// files needed by task 2
#define INPUT_TRAFFIC_PATH      "./data/traffic/traffic.in"
#define OUTPUT_TRAFFIC_PATH     "./traffic-predictions.out"

// csv positions
#define ORIGIN_IP_POS           2
#define FLOW_DURATION           4
#define BWD_PKTS_TOT            6
#define FLOW_PKTS_PAYLOAD_AVG   16

#define CRYPTOMINER_TIME 0.001    // 1.E-3 - linter fails scientific notation
#define ARRAY_SIZE(arr) (sizeof((arr)) / sizeof(*(arr)))

static const char   BENIGN_ORIGIN_IP[]      = "255.255.255.255";
static const double CRYPTOMINER_FLOW_PKTS[] = { 40, 50, 201, 220.5 };

int predict_traffic(char *traffic);
