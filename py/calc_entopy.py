import pyshark
import math
from pprint import pprint
from collections import Counter


n = 658405


nn = [2, 14, 8, 4, 14, 4, 19, 62, 53, 112, 12, 16, 2, 4, 2, 2, 4, 2, 6, 658043, 6, 14]


def get_entropy(n, nn):
    return -sum([i/n * math.log(i/n, 2) for i in nn])







def calculate_entropy(pcap_file):
    # Read the pcap file
    cap = pyshark.FileCapture(pcap_file, only_summaries=False)
    
    for i in cap:
        if (hasattr(i, 'transport_layer')):
            pprint(vars(i))

            
        
    # Concatenate the payload of all packets
    data = b''.join(packet.transport_layer.payload for packet in cap if hasattr(packet, 'transport_layer'))

    # Calculate the frequency of each byte
    freq_list = Counter(data)
    data_len = len(data)

    # Calculate the Shannon entropy
    entropy = -sum(f * math.log(f/data_len, 2) for f in freq_list.values()) / data_len
    return entropy

# Example usage

if __name__ == '__main__':
    print(get_entropy(n, nn))