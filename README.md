# PyScanner
## Port Scanning & Vulnerability Tool
PyScanner is a quick and easy port scanning tool used for reconnaissance. A major benefit to using PyScanner is that it significantly faster than some of the other tools out there like NMAP (BUT), if you are looking for more features, NMAP, RustScan, etc, are the tools to use. Although alot of the things that Other tools can do are good, those tools are made more for deeper topics, whereas PyScanner only scans for open & closed ports ports.

### Usage:
First, you are going to need the required python packages to run. You can install these using the command:
```
python -m pip install -r requirements.txt
```

After installing the requirements, it is pretty straight forward from there, you can just run the `pyscanner.py` script and go from there.

### Example:
```
$ python ./pyscanner.py -H localhost -p 8000 --vuln
[INFO] [EXTRA] Vuln mode enabled - Searching for possible vulnerabilities
[INFO] Scan Result for: kubernetes.docker.internal
[INFO] Scanning port: 8000
[+] OPEN: 8000/tcp        
[INFO] HTTP Headers:| "http://localhost:8000/"     
             Server | "SimpleHTTP/0.6 Python/3.9.2"
       Content-type | "text/html; charset=utf-8"   
     Content-Length |  680
[INFO] Possible Vulnerabilities:|
                ________________| exploit-db.com   
               | exploits/python/webapps/38411.txt
               | exploits/python/webapps/38738.txt 
               | exploits/python/webapps/39199.html
               | exploits/python/webapps/39821.txt 
               | exploits/python/webapps/40129.txt 
               | exploits/python/webapps/40799.txt 
               | exploits/python/webapps/48886.txt
               | exploits/python/webapps/48929.py 
               | exploits/python/webapps/43021.py 
               | exploits/python/webapps/46386.py 
               | exploits/python/webapps/47440.txt
               | exploits/python/webapps/47441.txt
               | exploits/python/webapps/47497.py
               | exploits/python/webapps/47879.md
               | exploits/python/webapps/48727.py
               | exploits/python/webapps/49495.py
               | exploits/python/webapps/49803.py
               | exploits/python/webapps/49930.txt
```