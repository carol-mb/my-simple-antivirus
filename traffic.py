"""traffic.py: Module solving task 2 predicting malicious traffic"""

INPUT_TRAFFIC_PATH  = "./data/traffic/traffic.in"
OUTPUT_TRAFFIC_PATH = "./traffic-predictions.out"

# csv positions
RESPONSE_IP             = 2
FLOW_DURATION           = 4
BWD_PKTS_TOT            = 6
FLOW_PKTS_PAYLOAD_AVG   = 16

CRYPTOMINER_LOW_TIME    = 0.01
CRYPTOMINER_FLOW_PKTS   = [40, 50, 201, 220.5]

BENIGN_ORIGIN_IP        = "255.255.255.255"

def predict_traffic(traffic):
    """
    Function that predicts if traffic is malicious or harmless.
    Returns 1 if malicious
    Returns 0 if harmless
    """
    response_ip = traffic[RESPONSE_IP]
    flow_duration = traffic[FLOW_DURATION].split(" ")[2].split(":")
    for i, time in enumerate(flow_duration):
        flow_duration[i] = float(time)
    flow_duration = flow_duration[2] + 60 * flow_duration[1]

    bwd_pkts_tot = int(traffic[BWD_PKTS_TOT])

    # bruteforce:
    # flow_duration different of 0
    # flow_pkts_payload.avg different of 0
    # bwd_pkts_tot greater than 40
    if flow_duration != 0 and bwd_pkts_tot >= 40 and \
        float(traffic[FLOW_PKTS_PAYLOAD_AVG]) != 0:
        return 1

    # cryptomining: flow_duration equal to 0
    # flow_pkts_payload.avg equal to 40, 201, 220.5
    if flow_duration <= CRYPTOMINER_LOW_TIME and \
        float(traffic[FLOW_PKTS_PAYLOAD_AVG]) in CRYPTOMINER_FLOW_PKTS and \
        response_ip != BENIGN_ORIGIN_IP:
        return 1

    # cyptomining: flow_duration greater than 1
    # flow_pkts_payload.avg equal to 50
    if flow_duration >= 1 and \
        float(traffic[FLOW_PKTS_PAYLOAD_AVG]) in CRYPTOMINER_FLOW_PKTS:
        return 1

    return 0
