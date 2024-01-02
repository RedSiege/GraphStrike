#!/usr/bin/env python3

import sys
import os
import time
import re
import random
import stat
import subprocess
from shutil import which, copy
import argparse
import socket
import threading
import datetime
from dateutil import parser
from dataclasses import dataclass
import requests
requests.packages.urllib3.disable_warnings()
from colorama import Fore, Style
from azure.cli.core import get_default_cli

# Have to define these vars here or else Python get angry. For all cases where we actually use them,
# they are imported + populated by the config file.
DRIVE_ID = None
SITE_ID = None
CLIENT_ID = None
CLIENT_SECRET = None
TENANT_ID = None

########################### OUTPUT FUNCTIONS ############################
def p_err(msg, exit):
    output = f"{Fore.RED}[-] {msg}{Style.RESET_ALL}"
    print(output)
    if exit:
        os._exit(-1)

def p_warn(msg):
    output = f"{Fore.YELLOW}[-] {msg}{Style.RESET_ALL}"
    print(output)

def p_success(msg):
    output = f"{Fore.GREEN}[+] {msg}{Style.RESET_ALL}"
    print(output)

def p_info(msg):
    output = f"{Fore.CYAN}[*] {msg}{Style.RESET_ALL}"
    print(output)

def p_info_plain(msg):
    output = f"{Fore.CYAN}{msg}{Style.RESET_ALL}"
    print(output)

def p_task(msg):
    bufferlen = 75 - len(msg)
    output = f"{msg}{'.' * bufferlen}"
    print(output, end="", flush=True)

# We can use some trickery to figure out what script loaded common.py.
# For the situations required, try and import our configuration variables.
script = os.path.basename(sys.argv[0])
if script == "GraphStrike.py" or (script == "provisioner.py" and sys.argv[1] == "delete"):
    try:
        from config import *
        configFound = True
    except:
        p_err("Cannot locate config file! Run the Provisioner and complete setup first.", True)

############################### GLOBALS #################################
userAgent = "Mozilla/6.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/103.0.0.0 Safari/537.36"
graphUrl = "https://graph.microsoft.com/v1.0/"
graphDriveUrl = f"{graphUrl}drives/{DRIVE_ID}/root/children"
graphFileUrl =  f"{graphUrl}sites/{SITE_ID}/drive/items/"

######################### CHECK PYTHON VERSION ##########################
def CheckVersion():
    major = sys.version_info[0]
    minor = sys.version_info[1]
    ver = major + (minor * .01)
    if major < 3:
        p_err(f"GraphStrike requires Python 3.8+! Client running: Python {ver}", True)
    if minor < 8:
        p_err(f"GraphStrike requires Python 3.8+! Client running: Python {ver}", True)

######################### GET AUTH TOKEN FUNCTION ########################
def GetAccessToken(clientId=CLIENT_ID, clientSecret=CLIENT_SECRET, tenantId=TENANT_ID):

    loginUrl = f"https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token"

    PARAMS = {  
        'client_id':clientId,
        'grant_type':'client_credentials',
        'scope':'https://graph.microsoft.com/.default',
        'client_secret':clientSecret
    }
    HEADERS = {
        'User-Agent':userAgent
    }

    while(True):
        r = requests.post(url = loginUrl, headers = HEADERS, data = PARAMS)
        if "200" in str(r):
            data = r.json()
            access_token = data['access_token']
            expires = data['expires_in'] - 500
            refreshTime = time.time() + expires
            return access_token, refreshTime
        
        # If a 400 is returned, the app isn't registered. User may have deleted it and then tried to run server again.
        elif "400" in str(r):
            p_err("Cannot fetch access token for app! App appears to have been deleted.", True)
            return None, None
            
        # If we otherwise didn't get a 200, wait a second and try again in the hopes it was a server error.
        else:
            p_warn("Failed to retrieve an access token, sleeping 60 seconds and trying again...")
            time.sleep(60)

########################### LIST FILES IN SHAREPOINT ################################
def ListFiles(access_token):
    URL = graphDriveUrl
    HEADERS = {
        'User-Agent':userAgent,
        'Authorization':'Bearer ' + access_token
    }
    while(True):
        try:
            r = requests.get(url = URL, headers = HEADERS)
            if "200" in str(r):
                data = r.json()
                break
            elif "429" in str(r):
                p_warn("Hit rate limit! Sleeping for 1 minute and then retrying...\nPsst consider increasing your sleep times!")
                time.sleep(60)
            else:
                p_warn(f"CheckBeacons request non-success code: {str(r)}")
                time.sleep(1)
        except:
            p_warn(f"CheckBeacons request exception: {str(r)}")
            time.sleep(1)

    driveItems = dict()
    for obj in data['value']:
        # Store id for use in creating file URI's
        id = obj['id']
        # Store name for correlating ts tasking file and Beacon output file
        name = obj['name']
        # Store size so we can tell when TS tasking file has changed + is available for new tasking
        size = obj['size']
        # Store last modified date/time so we can tell how long a TS task has been queued without Beacon receiving it
        lastModified = obj['lastModifiedDateTime']
        # Add drive item to dictionary
        driveItems[name] = {'id': id, 'size': size, 'lastModified': lastModified}

    return driveItems

############################### DELETE FILES #######################################
def DeleteFile(access_token, fileId):
    URL = graphFileUrl + fileId
    HEADERS = {
        'User-Agent':userAgent,
        'Authorization':'Bearer ' + access_token,
    }

    while(True):
        r = requests.delete(url = URL, headers = HEADERS)
        if "204" in str(r) or "404" in str(r):
            break
        else:
            p_warn(f"Encountered non-success code when deleting files: {str(r)} Data is: {str(r.content)}")
            time.sleep(1)