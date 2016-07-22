# -*- coding: utf-8 -*-
"""
Passive DNS by IP/domain
Virus Total private api services
Input: ipaddress[<ipaddress>...]
Optional Params: --ip passivedns query by IP
                 --domain passivedns query by domain
Output: passive DNS information
Created on Tue Jul 12 10:48:19 2016

@author: edgarasm
"""
import sys
import httplib, json, requests

#TODO: read domain/ips from .config file 
#TODO: add file output option

# read api keys and work to parse
def init():
    api_file = open('passiveDNS.config', 'r')
    config = {}
    config['api'] = api_file.readline()
    api_file.close()
    return config
# read work in forms domains from the file

def vtIP(ip):
    try: 
        config = init()
        params = {'ip': ip, 'apikey': config['api'] }
        url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
        response = requests.get(url, params = params)
        response_json = response.json()
        return response_json
    except Exception as e:
        print('[-Errno {0}] {1}'.format(e.errno, e.strerror))

def vtDomain(addr):
    try: 
        config = init()
        params = {'domain': addr, 'apikey': config['api']}
        url = 'https://www.virustotal.com/vtapi/v2/domain/report'
        response = requests.get(url, params=params)
        response_json = response.json()
        return response_json
    except Exception as e:
        print('[-Errno {0}] {1}'.format(e.errno, e.strerror))

def format_vtIP(out_vt):
    try:
        print 'Historic Passive DNS resolutions [last_resolved] [hostname]'
        for resolution in sorted(out_vt['resolutions'], key = lambda key:key['last_resolved'], reverse = True):
            print resolution['last_resolved'].split()[0], resolution['hostname']
        print 
    except KeyError:
        print 'Passive DNS data is not available'
        print

    try: 
        if out_vt['detected_url']:   
            print 'Detected URLs [scan_date] [url]'
            for url in sorted(out_vt['detected_urls'], key = lambda key:key['scan_date'], reverse = True):
                print url['scan_date'], url['url']
    except KeyError:
        print 'Detected URLs data is not available'
        print
    return

def format_vtDomain(out_vt):
    print out_vt['whois']
    print 
    print 'Web Reputation domain info:'
    try:
        print 'Verdict: ' + out_vt['Webutation domain info']['Verdict']
        print 'Adult Content: ' + out_vt['Webutation domain info']['Adult content']
        print 'Safety score: ' + str(out_vt['Webutation domain info']['Safety score'])
        print 
    except KeyError:
        print "Reputation data is not available"
        print

    try:
        print 'Historic Passive DNS resolutions [last_resolved] [hostname]'
        for resolution in sorted(out_vt['resolutions'], key = lambda key:key['last_resolved'], reverse = True):
            print resolution['last_resolved'].split()[0], resolution['ip_address']
        print 
    except KeyError:
        print 'Passive DNS data is not available'
        print

    try:
        if out_vt['detected_urls']:
            print 'Detected URLs [scan_date] [url]'
            for url in sorted(out_vt['detected_urls'], key = lambda key:key['scan_date'], reverse = True):
                print url['scan_date'], url['url']
    except KeyError:
        print 'Detected URLs data is not available'
        print

def main():
    if not sys.argv[1:]:
        print 'usage: .passiveDNS.py [--ip] [--domain] <ip_address>/<domain>'
        sys.exit(1)
    if sys.argv[1] =='--ip': 
        ip_address = sys.argv[2]
        out_vt = vtIP(ip_address)
        # check if ip was found before calling the method
        if out_vt['verbose_msg']=='IP address in dataset':
            format_vtIP(out_vt)
        else: 
            print '[-]Error: ' + out_vt['verbose_msg']      
    elif sys.argv[1] == '--domain':
        domain = sys.argv[2]
        out_vt = vtDomain(domain)

        # check if domain was found before calling the method
        if out_vt['verbose_msg']=='Domain found in dataset':
            format_vtDomain(out_vt)
        else:
            print '[-]Error: ' + out_vt['verbose_msg'] + domain
       
    
if __name__ == '__main__':
    main()