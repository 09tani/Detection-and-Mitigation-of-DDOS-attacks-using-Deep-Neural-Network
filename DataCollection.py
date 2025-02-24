import time
import threading
from scapy.all import sniff, IP, TCP

# Dictionary to store active flows
flows = {}

# Lock for thread-safe flow updates
flows_lock = threading.Lock()

# Define a timeout (in seconds) to consider a flow complete if no new packets arrive
FLOW_TIMEOUT = 60

def process_packet(packet):
    """Process each packet captured by Scapy."""
    if packet.haslayer(IP) and packet.haslayer(TCP):
        ip_layer = packet[IP]
        tcp_layer = packet[TCP]

        # Define the flow key: (src, dst, sport, dport, protocol)
        key = (ip_layer.src, ip_layer.dst, tcp_layer.sport, tcp_layer.dport, 'TCP')

        with flows_lock:
            # Initialize the flow if it's the first packet seen
            if key not in flows:
                flows[key] = {
                    'Dst Port': tcp_layer.dport,
                    'start_time': packet.time,
                    'end_time': packet.time,
                    'pkt_count': 0,
                    'fwd_pkt_count': 0,
                    'bwd_pkt_count': 0,
                    'fwd_header_len': 0,
                    'bwd_header_len': 0,
                    'PSH Flag Cnt': 0,
                    'Init Fwd Win Byts': tcp_layer.window,  # capture from first packet
                    'Fwd Act Data Pkts': 0,
                    'Label': 'unknown',  # Placeholder for future classification
                    'initiator': ip_layer.src  # assume the first packet’s src is the initiator
                }

            flow = flows[key]
            flow['end_time'] = packet.time  # update last seen time
            flow['pkt_count'] += 1

            # Determine packet direction: forward if from initiator; else backward.
            if ip_layer.src == flow['initiator']:
                flow['fwd_pkt_count'] += 1
                # Calculate TCP header length in bytes (dataofs is in 32-bit words)
                fwd_hdr_len = tcp_layer.dataofs * 4
                flow['fwd_header_len'] += fwd_hdr_len

                # Count PSH flag if set (0x08 is the PSH flag)
                if tcp_layer.flags & 0x08:
                    flow['PSH Flag Cnt'] += 1

                # Count as an actual data packet if payload exists
                if len(tcp_layer.payload) > 0:
                    flow['Fwd Act Data Pkts'] += 1
            else:
                flow['bwd_pkt_count'] += 1
                bwd_hdr_len = tcp_layer.dataofs * 4
                flow['bwd_header_len'] += bwd_hdr_len

                if tcp_layer.flags & 0x08:
                    flow['PSH Flag Cnt'] += 1

def compute_flow_metrics(flow):
    """Compute derived metrics for a given flow."""
    duration = flow['end_time'] - flow['start_time']
    # Avoid division by zero
    flow_duration = duration if duration > 0 else 1

    return {
        'Dst Port': flow['Dst Port'],
        'Flow Duration': duration,
        'Flow Pkts/s': flow['pkt_count'] / flow_duration,
        'Fwd Header Len': flow['fwd_header_len'],
        'Bwd Header Len': flow['bwd_header_len'],
        'Fwd Pkts/s': flow['fwd_pkt_count'] / flow_duration,
        'Bwd Pkts/s': flow['bwd_pkt_count'] / flow_duration,
        'PSH Flag Cnt': flow['PSH Flag Cnt'],
        'Init Fwd Win Byts': flow['Init Fwd Win Byts'],
        'Fwd Act Data Pkts': flow['Fwd Act Data Pkts'],
        'Label': flow['Label']
    }

def flush_expired_flows():
    """Periodically flush flows that have been inactive for longer than FLOW_TIMEOUT."""
    while True:
        current_time = time.time()
        expired_keys = []

        with flows_lock:
            for key, flow in flows.items():
                if current_time - flow['end_time'] > FLOW_TIMEOUT:
                    expired_keys.append(key)

            # Process and remove expired flows
            for key in expired_keys:
                flow = flows.pop(key)
                metrics = compute_flow_metrics(flow)
                # Here, you could write to a database, file, or send the metrics to another service.
                print("Flow Metrics:", metrics)

        # Sleep before next check
        time.sleep(10)

def start_packet_sniffing():
    """Start sniffing packets."""
    sniff(prn=process_packet, store=False)

if __name__ == '__main__':
    # Start the flow flushing thread
    flush_thread = threading.Thread(target=flush_expired_flows, daemon=True)
    flush_thread.start()

    print("Starting packet capture...")
    start_packet_sniffing()
