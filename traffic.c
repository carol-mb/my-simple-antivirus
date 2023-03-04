#include "traffic.h"

static int check_flow_pkts_avg(float flow_pkts_avg)
{
	int size = ARRAY_SIZE(CRYPTOMINER_FLOW_PKTS);

	for (int i = 0; i < size; ++i)
		if (flow_pkts_avg == CRYPTOMINER_FLOW_PKTS[i])
			return 1;

	return 0;
}

// predicts if given traffic is malicious or harmless
// returns 1 if malicious
// returns 0 if harmless
int predict_traffic(char *traffic)
{
	char origin_ip[16];
	double flow_duration = 0.f;
	double bwd_pkts_tot = 0.f;
	double flow_pkts_payload_avg = 0.f;

	int counter = 0;

	char *p = strtok(traffic, ",");
	while (p) {
		// get origin ip
		if (counter == ORIGIN_IP_POS)
			strcpy(origin_ip, p);

		// calculate flow_duration
		if (counter == FLOW_DURATION)
			flow_duration = atof(strrchr(p, ':') + 1);

		// calculate bwd_pkts_tot
		if (counter == BWD_PKTS_TOT)
			bwd_pkts_tot = atof(p);

		// calculate flow_pkts_payload_avg
		if (counter == FLOW_PKTS_PAYLOAD_AVG)
			flow_pkts_payload_avg = atof(p);

		p = strtok(NULL, ",");
		counter++;
	}

    // bruteforce:
    // flow_pkts_payload.avg != 0
    // bwd_pkts_tot > 40
	if (flow_duration != 0 && flow_pkts_payload_avg != 0 && bwd_pkts_tot >= 40)
		return 1;

    // cryptomining: when flow_duration nearly 0
	if (flow_duration <= CRYPTOMINER_TIME &&
		strcmp(origin_ip, BENIGN_ORIGIN_IP) != 0 &&
		check_flow_pkts_avg(flow_pkts_payload_avg))
		return 1;

    // cyptomining: when flow_duration > 1
	if (flow_duration >= 1 &&
		check_flow_pkts_avg(flow_pkts_payload_avg))
		return 1;

	return 0;
}
