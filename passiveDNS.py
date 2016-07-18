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

def vtIP(ip):
    try: 
        params = {'ip': ip, 'apikey': '3b56547d780fd9112d729d4d20081d259d4fd7c00cdb9edba9024241ba5bb05c' }
        url = 'https://www.virustotal.com/vtapi/v2/ip-address/report'
        response = requests.get(url, params = params)
        response_json = response.json()
        return response_json
    except Exception as e:
        print('[-Errno {0}] {1}'.format(e.errno, e.strerror))

def vtDomain(addr):
    try: 
        params = {'domain': addr, 'apikey': '3b56547d780fd9112d729d4d20081d259d4fd7c00cdb9edba9024241ba5bb05c'}
        url = 'https://www.virustotal.com/vtapi/v2/domain/report'
        response = requests.get(url, params=params)
        response_json = response.json()
        return response_json
    except Exception as e:
        print('[-Errno {0}] {1}'.format(e.errno, e.strerror))

def format_vtIP(out_vt):
    print 'Historic Passive DNS resolutions [last_resolved] [hostname]'
    for resolution in sorted(out_vt['resolutions'], key = lambda key:key['last_resolved'], reverse = True):
        print resolution['last_resolved'].split()[0], resolution['hostname']
    print 
    print 'Detected URLs [scan_date] [url]'
    for url in sorted(out_vt['detected_urls'], key = lambda key:key['scan_date'], reverse = True):
        print url['scan_date'], url['url']
    return

def format_vtDomain(out_vt):
    print out_vt['whois']
    print 
    print 'Web Reputation domain info:'
    print 'Verdict: ' + out_vt['Webutation domain info']['Verdict']
    print 'Adult Content: ' + out_vt['Webutation domain info']['Adult content']
    print 'Safety score: ' + str(out_vt['Webutation domain info']['Safety score'])
    print 
    print 'Historic Passive DNS resolutions [last_resolved] [hostname]'
    for resolution in sorted(out_vt['resolutions'], key = lambda key:key['last_resolved'], reverse = True):
        print resolution['last_resolved'].split()[0], resolution['ip_address']
    print 
    print 'Detected URLs [scan_date] [url]'
    for url in sorted(out_vt['detected_urls'], key = lambda key:key['scan_date'], reverse = True):
        print url['scan_date'], url['url']
    return

def main():
    if not sys.argv[1:]:
        print 'usage: .geoIP.py [--ip] [--domain] <ip_address>/<domain>'
        sys.exit(1)
    if sys.argv[1] =='--ip': 
        ip_address = sys.argv[2]
        out_vt = vtIP(ip_address)
        format_vtIP(out_vt)
    elif sys.argv[1] == '--domain':
        domain = sys.argv[2]
        out_vt = vtDomain(domain)
        format_vtDomain(out_vt)
       
    
if __name__ == '__main__':
    main()