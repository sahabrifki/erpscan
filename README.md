# ERPSCAN EBS Pentesting tool

## ERPScan_EBS_Pentesting_Tool.py
* This is ERPSCAN EBS Pentesting tool for ERPScan site. It is a wrapper for ERPSCAN EBS checking modules.
There are 4 main modules _(`1` module uses EBS Users' passwords decryptor `ebsDecrypt.py`)_:
1. EBS DB Users Brute-force (dbUsersBforce.py),
2. EBS Users Brute-force (ebsUsersBforce.py),
3. EBS Java Serialization test (javaSerDetect.py),
4. EBS XML Serialization test (xmlSerDetect.py).

### Help
* You should install absent libraries from `requirements.txt` file.

```
usage: ERPScan_EBS_Pentesting_Tool.py [-h] [-m MODULE] [-H HOST] [-dP DPORT]
                                      [-eP EPORT] [-wP WPORT] [-eU EURL]
                                      [-wU WURL] [-s] [-dS SID] [-dD DEC]
                                      [-dF FILE] [--timeout TIMEOUT] [-v]

ERPSCAN EBS Pentesting tool  v1.0

by ERPScan (c) 2018

It is a wrapper for ERPSCAN EBS checking modules.
There are 4 main modules:
1. EBS DB Users Brute-force (dbUsersBforce.py) (also includes `ebsDecrypt.py`),
2. EBS Users Brute-force (ebsUsersBforce.py),
3. EBS Java Serialization test (javaSerDetect.py),
4. EBS XML Serialization test (xmlSerDetect.py),

optional arguments:
  -h, --help            show this help message and exit
  -m MODULE, --module MODULE
                        Choose a module to execute (default: 0 - run all)
  -H HOST, --host HOST  Target host (default: 127.0.0.1). Example: ebs.example.com
  -dP DPORT, --dport DPORT
                        DB port (default: 1521)
  -eP EPORT, --eport EPORT
                        EBS web port (default: 8000)
  -wP WPORT, --wport WPORT
                        WebLogic port (default: 7001)
  -eU EURL, --eurl EURL
                        EBS target URL (default: OA_HTML/iesRuntimeServlet)
  -wU WURL, --wurl WURL
                        WebLogic target URL (default: wls-wsat/CoordinatorPortType)
  -s, --ssl             Enable SSL
  -dS SID, --sid SID    DB SID (default: EBSDB)
  -dD DEC, --dec DEC    Try to decrypt EBS Users Passwords? Y/N (default: Y)
  -dF FILE, --file FILE
                        Add file name to save all results (default: dbCheckResults.txt)
  --timeout TIMEOUT     Connection timeout in seconds. Default value is already used in some scripts. By changing it, you take responsibility for a proper module execution
  -v, --verbose         Verbose mode
```

### Usage

```
$ ERPScan_EBS_Pentesting_Tool.py -m 0
```

# DATABASE LEVEL

## dbUsersBforce.py
* Script brutes DB standard users with predefined passwords.
Also it can grab EBS users' passwords from `APPS.fnd_user` table and in the case password hashing is not `on`
it decrypts them with the `ebsDecrypt.py` module. All founds will be saved in `dbCheckResults.txt` file.

### Help
* You should install `cx_Oracle` for working.

```
usage: dbUsersBforce.py [-h] [-H HOST] [-P PORT] [-s SID] [-d DEC] [-v]

EBS DB Users Brute-force Python Script. It tests for default DB users with the predefined passwords. Also it can check
whether any bruted DB user can decrypt EBS Users passwords (of course if Password Hashing is not implemented).

optional arguments:
  -h, --help            show this help message and exit
  -H HOST, --host HOST  DB host (default: 127.0.0.1). Example: ebs.example.com
  -P PORT, --port PORT  DB port (default: 1521)
  -s SID, --sid SID     DB SID (default: EBSDB)
  -d DEC, --dec DEC     Try to decrypt EBS Users Passwords? Y/N
  -v, --verbose         verbose mode

```

### Usage

```
$ dbUsersBrutforce.py -H ebs.example.com -s EBSDB -d Y
```

## ebsDecrypt.py
* Script can decrypt EBS users passwords in the case `apps` user passwords is known. It handles `new` (SHA-1 + 3DES) and `old` (SHA-1-like + ARC4) encryptions.

### Help
* You should install `pyjks` for working.

```
usage: ebsDecrypt.py [-h] [-k KEY] [-d DATA]

Script can decrypt EBS users' passwords in case `apps` user passwords is known.
It handles `new` (SHA-1 + triple-DES) and `old` (SHA-1-like + RC4) encryption.

optional arguments:
  -h, --help            show this help message and exit
  -k KEY, --key KEY     APPS user password (default: APPS
  -d DATA, --data DATA  Decrypted data (test value: C4E9B591098EA0)
```

### Usage
* `apps` user password should be uppercase.

```
$ decrypt.py -k APPS -d ZH4715DC7E9C2213F7CD56D44CE1CB8625FB71D0F4935EFEAE5B8CA66117B9C2D6A1E733BA80005F4CD19706A03218E8C5E4
```

# EBS LEVEL

## ebsUsersBforce.py
* Script brutes EBS default users with predefined passwords. It handles two types of auth version (don't mix with SSO!).

### Help

```
usage: ebsUsersBforce.py [-h] [-H HOST] [-P PORT] [-s] [-t TIMEOUT] [-v]

EBS Users Brute-force python script brutes EBS default users with predefined passwords.

optional arguments:
  -h, --help            show this help message and exit
  -H HOST, --host HOST  EBS host (default: 127.0.0.1). Example: ebs.example.com
  -P PORT, --port PORT  EBS web port (default: 8000)
  -s, --ssl             enable SSL
  -t TIMEOUT, --timeout TIMEOUT
                        HTTP connection timeout in second (default: 10)
  -v, --verbose         verbose mode
```

### Usage

```
$ ebsUsersBforce.py -H ebs.example.com -P 8000
```

## javaSerDetect.py
* EBS python script for Java Serialization sleep payloads testing based on Apache Commons Collections 3.
It sends special sleep payloads and checks the response time value. If the response time value
is more than 10 seconds, thus the testing host is potentially vulnerable to Java Deserialization attacks.

### Help

```
usage: javaSerDetect.py [-h] [-H HOST] [-P PORT] [-u URL] [-s] [-t TIMEOUT]
                        [-v]

EBS python script for Java Serialization sleep payloads testing based on Apache Commons Collections 3.

optional arguments:
  -h, --help            show this help message and exit
  -H HOST, --host HOST  EBS host (default: 127.0.0.1). Example: ebs.example.com
  -P PORT, --port PORT  EBS web port (default: 8000)
  -u URL, --url URL     EBS target URL (default: OA_HTML/iesRuntimeServlet)
  -s, --ssl             enable SSL
  -t TIMEOUT, --timeout TIMEOUT
                        HTTP connection timeout in second (default: 15)
  -v, --verbose         verbose mode
```

### Usage

```
$ javaSerDetect.py -H ebs.example.com -P 8000
```


# WEBLOGIC LEVEL

## xmlSerDetect.py
* Python script for XML Serialization sleep payload testing based on `CVE-2017-3506 & 10271`.
It sends special sleep payloads and checks the response time value. If the response time value
is more than 10 seconds, thus the testing host is potentially vulnerable to XML Deserialization attacks.

### Help

```
usage: xmlSerDetect.py [-h] [-H HOST] [-P PORT] [-u URL] [-s] [-t TIMEOUT]
                       [-v]

EBS python script for XML Serialization sleep payload testing based on `CVE-2017-3506 & 10271`.

optional arguments:
  -h, --help            show this help message and exit
  -H HOST, --host HOST  WebLogic host (default: 127.0.0.1). Example: ebs.example.com
  -P PORT, --port PORT  WebLogic port (default: 7001)
  -u URL, --url URL     WebLogic target URL (default: wls-wsat/CoordinatorPortType)
  -s, --ssl             enable SSL
  -t TIMEOUT, --timeout TIMEOUT
                        HTTP connection timeout in second (default: 15)
  -v, --verbose         verbose mode
```


### Usage

```
$ xmlSerDetect.py -H ebs.example.com -P 7001
```
