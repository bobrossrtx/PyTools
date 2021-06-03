
#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import division
__version__ = "0.3.3"

import optparse
import socket
from socket import *
import requests
import colorama
from colorama import Fore, Back, Style
colorama.init(autoreset=True)
from re import sub
import csv

INFO = Fore.YELLOW
SUCCESS = Fore.GREEN
FAIL = Fore.RED
SETTING = Fore.LIGHTCYAN_EX
RESET = Fore.RESET
EXTRA = Fore.LIGHTGREEN_EX

def findExploitResults(file_in, path_in, name_in="exploits"):
  if type(name_in) == str:
    if "paper" in name_in.lower(): url = "papers"
    elif "shellcodes" in name_in.lower(): url = "shellcodes"
    elif "exploits" in name_in.lower(): url = "exploits"
    else: url = name_in
  else: url = name_in


  with open(f'{path_in}/{file_in}', "r", encoding='cp850') as file:
    csvFile = csv.reader(file)
    for lines in csvFile:
      for i in lines:
        i = i.lower()
        if type(url) == list:
          for a in url:
            a = a.lower()
            if a in i:
              print(f"               | {i}")

def printVersion(version, progName):
  print(f"{SETTING}{progName.title()} Version {EXTRA}~ {Fore.LIGHTRED_EX}{Style.BRIGHT}V{version}^")


def connScan(tgtHost, tgtPort, quiet=False, vuln=False):
  try:
    connSkt = socket(AF_INET, SOCK_STREAM)
    connSkt.connect((tgtHost, tgtPort))
    print(f'{SUCCESS}[+] OPEN: {SETTING}{tgtPort}{RESET}/tcp')
    if not quiet:
      try:
        connSkt.send("PyScanner\r\n".encode('utf-8'))
        raw = connSkt.recv(2048)
        if "doctype html" in raw.decode('utf-8').lower():
          try:
            tgtIP = gethostbyname(tgtHost)
            resp = requests.get(f"http://{tgtHost}:{tgtPort}")
            print(f'{INFO}[INFO]{RESET} HTTP Headers:| {INFO}\"http://{tgtHost}:{tgtPort}/\"')
            if quiet == False:
              print(f"""             Server | {INFO}\"{resp.headers["Server"]}{RESET}\"
       Content-type | {INFO}\"{resp.headers["Content-type"]}\"{RESET}
     Content-Length |  {INFO}{resp.headers["Content-Length"]}""")
              if vuln:
                print(f"{INFO}[INFO]{RESET} Possible Vulnerabilities:|\n\
                ________________| {SUCCESS}exploit-db.com")
                if "python" in resp.headers["Server"].lower():
                  findExploitResults("files_exploits.csv", "./exploitdb", ["python/webapps"])
                elif "apache" in resp.headers["Server"].lower():
                  findExploitResults("files_exploits.csv", "./exploitdb", ["apache"])
            else: pass
          except:
            print(f'{FAIL}[-] ERROR:{RESET} Unable to read HEADERS')
        else:
          print(f"{INFO}[INFO] {RESET}{raw.decode('utf-8')}")
          # OpenSSH
          if vuln:
                print(f"{INFO}[INFO]{RESET} Possible Vulnerabilities:|\n\
                ________________| {SUCCESS}exploit-db.com")
                if "python" in resp.headers["Server"].lower():
                  findExploitResults("files_exploits.csv", "./exploitdb", ["openssh"])
                elif "apache" in resp.headers["Server"].lower():
                  findExploitResults("files_exploits.csv", "./exploitdb", ["apache"])
      except:
        print(f"{FAIL}[-] ERROR:{RESET} Could not send packets")
    connSkt.close()
  except:
      print(f'{FAIL}[-] CLOSED: {SETTING}{tgtPort}{RESET}/tcp',)


def portScan(tgtHost, tgtPorts, quiet=False, vuln=False):
  try:
    tgtIP = gethostbyname(tgtHost)
  except:
    print(f'{FAIL}[-] ERROR: Cannot resolve \'{tgtHost}\'{RESET}: Unknown host')
    return
  try:
    tgtName = gethostbyaddr(tgtIP)
    print(f'{INFO}[INFO] Scan Result for: {SETTING}{tgtName[0]}{RESET}')
  except:
    print(f'{INFO}[INFO] Scan Result for: {tgtIP}')

  setdefaulttimeout(1)
  for tgtPort in tgtPorts:
    if not quiet:
      print(f"{INFO}[INFO] Scanning port: {SETTING}{tgtPort}{RESET}")
    connScan(tgtHost, int(tgtPort), quiet=quiet, vuln=vuln)


def main(version: str, progName: str) -> int:
  # Initialize parser
  parser = optparse.OptionParser(f'{progName} -H {SETTING}<target host> {RESET}-p {SETTING}<target port>{RESET}')

  parser.set_description("PyScanner is a quick and easy port scanning tool used for reconnaissance. A major benefit to using PyScanner is that it significantly faster than some of the other tools out there like NMAP (BUT), if you are looking for more features, NMAP, RustScan, etc, are the tools to use. Although alot of the things that Other tools can do are good, those tools are made more for deeper topics, whereas PyScanner only scans for open & closed ports ports.")

  # Add command line arguments
  parser.add_option('-H', '--host', dest='tgtHost', type='string', help=f'specify target host.', metavar=f'{SETTING}HOST{RESET}')
  parser.add_option('-p', '--port', dest='tgtPort', type='string', help=f'specify target port[s] separated by a comma (80,22).', metavar=f'{SETTING}PORTS{RESET}')
  parser.add_option('-o', '--output', dest='outputFile', type='string', help='specify file to write the output to.', metavar=f'{SETTING}FILE{RESET}')
  parser.add_option('-v', '--version', action='store_true', dest='version', default=False, help='show PyScanner\'s version.')
  parser.add_option('-q', '--quiet', action='store_true', dest='quiet', default=False, help='disable log messages to STDOUT.')
  parser.add_option('--vuln', action='store_true', dest='vuln', default=False, help='show possible vulnerabilities.')

  # Parse arguments
  (options, args) = parser.parse_args()

  ## Options
  # Targets
  tgtHost = options.tgtHost
  tgtPorts = list()
  if options.tgtPort != "-":
    tgtPorts = str(options.tgtPort).split(',')
    quiet = options.quiet
  else:
    quiet = True
    min_ports = 0
    max_ports = 10
    for port in range(min_ports, max_ports + 1):
      tgtPorts.append(port)

  if (options.version):
    printVersion(version, progName)
    return 0
  elif (tgtHost == None) | (tgtPorts[0] == None):
    parser.print_help()
    exit(1)
  
  vuln = options.vuln

  # Extras
  if (quiet): print(f"{INFO}[INFO]{EXTRA} [EXTRA]{RESET} Quiet mode enabled - Disabling STDOUT")
  if (vuln): print(f"{INFO}[INFO]{EXTRA} [EXTRA]{RESET} Vuln mode enabled - Searching for possible vulnerabilities")
  
  # Scan the hosts
  portScan(tgtHost, tgtPorts, quiet=quiet, vuln=vuln)
  return 0


if __name__ == '__main__':
  main(__version__, "pyscanner")