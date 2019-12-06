''' Takes an output script with multiple lines for each host and 
 aggregates them all in one line. The header becomes:
 IP,HOST,< --- PORTS --->, < --- PLUGIN OUTPUT KEYS --- >



  @Author: Gabrio Tognozzi
  @Company: Quantum Leap
'''


import csv
from collections import defaultdict
from IPython import embed;
from pdb import set_trace;
import argparse

H_PORT       = "Port"
H_PLUGINKEY  = "Plugin Key"
H_PLUGINVAL  = "Plugin Value"
H_IP     = "IP"
H_HOST   = "Host"
H_PROTO  = "Proto"
H_SERVICE = "Service"
H_PRODUCT = "Product"
H_NSE_OUT = "NSE Script Output"

def main():
    ''' Takes a csv generated with nmap-scan-to-csv and 
     aggregates its rows.
    
    This script expects to find the following csv columns:
    'IP', 'Host', 'Proto', 'Port',
    'Service', 'Product', 'Service FP',
    'NSE Script ID', 'NSE Script Output',
    'Notes', 'Plugin ID', 'Plugin Key',
    'Plugin Value'
    '''
    parser = argparse.ArgumentParser(description=main.__doc__)
    parser.add_argument("infile",help="nmap-scan-to-csv generated csv")
    parser.add_argument("outfile",help="output file for aggregated csv")
    args = parser.parse_args()

    csvpath = args.infile
    outcsvpath = args.outfile
    
    data = csv.DictReader(open(csvpath))
    data = [ row for row in data ]
    
    # Create list of all seen ports and plugin keys,
    # they will became columns.
    ports = set()
    plugin_keys = set()
    for row in data:
        port = row[H_PORT]
        if port != "" and port != H_PORT:
            ports.add(port)
        
        plugin_key = row[H_PLUGINKEY]
        if plugin_key != "" and plugin_key != H_PLUGINKEY:
            plugin_keys.add(plugin_key)
        
    columns = [H_IP,H_HOST]+list(ports)+list(plugin_keys)
    
    
    # Build, for each host, his dictionary that represents
    # a row value.
    hosts_dict = defaultdict(lambda:{})
    
    
    for row in data:
        
        ip = row[H_IP]
        if ip == H_IP:
            continue
        host_dict = hosts_dict[ip]
        host_dict[H_IP]=ip
    
        host = row[H_HOST]
        host_dict[H_HOST]=host
        
        port = row[H_PORT]
        if port != "" and port !=H_PORT:
            port_value = ",".join( [ 
                                row[H_PROTO],
                                row[H_SERVICE],
                                row[H_PRODUCT],
                                row[H_NSE_OUT] ])
            host_dict[port]=port_value
        
        plugin_key = row[H_PLUGINKEY]
        if plugin_key != "" and plugin_key !=H_PLUGINKEY:
            plugin_value = row[H_PLUGINVAL]
            host_dict[plugin_key]=plugin_value
                
            
    hosts_dict = dict(hosts_dict)
    
    with open(outcsvpath,"w") as csvfile:
        fieldnames = columns
        writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
        writer.writeheader()
        for h in hosts_dict:
            writer.writerow(hosts_dict[h])
    
if __name__=="__main__":
    main()
