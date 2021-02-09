#!/usr/bin/env python3

from helpers import *

from scapy.all import *
from datetime import datetime
import pandas as pd
import matplotlib.pyplot as plt
import argparse

def get_args():
    parser = argparse.ArgumentParser(description='This script visualizes how much flows are created for each certain time window as time-serices plot.')

    parser.add_argument('filename', type=str, help='The .pcap/.pcaping file to anlayze.')
    parser.add_argument('fig_name', type=str, help='The filename to be save (.png or .jpg).')

    parser.add_argument('-p', '--protocol', default='tcp', type=str, help='Which L4 protocol to analyze. Either tcp, udp or both is acceptable.')
    parser.add_argument('-e', '--exception', default=None, type=str, help='IP addresses which are not')
    parser.add_argument('-w', '--window', default='1min', type=str, help='The window (time range) for resampling')
    parser.add_argument('--figsize', default=10, type=int, help='The figure size')

    return parser.parse_args()


def main():
    args = get_args()
    
    # load packets
    pkts = rdpcap(args.filename)

    # filter out packets which does not need SNAT
    pkts = filter(lambda x: communicates_with_global_endpoints(x), pkts)
    pkts = filter(lambda x: not communicates_with(x, "168.63.129.16"), pkts)

    # for each 5tuple, store TCP SYN requests (all TCP packets with SYN flag, but without ACK flag).
    syn_requests_by_fivetuple = dict()
    for p in filter(is_tcp_syn, pkts):
        key = FiveTuple(p)
        if key in syn_requests_by_fivetuple:
            syn_requests_by_fivetuple[key].append(p)
        else:
            syn_requests_by_fivetuple[key] = [p]

    df_snat_request = list()
    for ft, syn_packets in syn_requests_by_fivetuple.items():
        # pick the first SYN packet from a given 5 tuple.
        syn_request_times = [datetime.fromtimestamp(p.time) for p in syn_requests_by_fivetuple[ft]]
        argmin = syn_request_times.index(min(syn_request_times))
        p = syn_requests_by_fivetuple[ft][argmin]
        
        df_snat_request.append({
            'time_syn_request': min(syn_request_times),
            'src': p[IP].src,
            'src_port': p[IP].sport,
            'dst': p[IP].dst,
            'dst_port': p[IP].dport,
            'protocol': p[IP].proto,
            'count': 1 # dummy
        })

    df_snat_request = pd.DataFrame(df_snat_request)

    fig, ax = plt.subplots(figsize=(args.figsize, int(args.figsize*0.6)))
    fig.patch.set_facecolor('white')
    df_snat_request.resample(args.window, label='right', closed='right', on='time_syn_request')['count'].sum().plot()
    ax.set_title(f"SNAT Requests per {args.window}")
    plt.xlabel("Datetime")
    plt.ylabel("# of SNAT Requests")
    plt.savefig(args.fig_name)

if __name__ == '__main__':
    main()



