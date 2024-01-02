#!/usr/bin/env python3

import sys
import os

# Add folder containing required imports to path
sys.path.append(f"{os.getcwd()}/../inc")

# Import our GraphStrike assets
from banner import *
from common import *

tenantId = None
clientSecret = None
appId = None
siteId = None
driveId = None
access_token = None
sleepTime = None
httpGetPrefix = None
httpPostPrefix = None
csDir = None
bidDelimiter = "pD9-tK"

METADATA_SCRIPT = "../inc/cs-decrypt-metadata.py"
GRAPHSTRIKE_SCRIPT = "../GraphStrike.py"

def AzCli (args_str):
    args_str = f"{args_str} --only-show-errors"
    args = args_str.split()
    cli = get_default_cli()
    cli.invoke(args, out_file = open(os.devnull, 'w'))
    if cli.result.result:
        return cli.result.result
    elif cli.result.error:
        raise cli.result.error
    return True

def DepCheck(command, packageName):
    # Check for required dependencies:
    p_task(f"Checking to see if {command} is installed...")
    if which(f"{command}") is not None:
        p_success("SUCCESS!")
    else:
        p_err("ERROR!", False)
        p_err(f"Cannot locate {packageName}, try installing with: apt-get -y install make", True)

def DeleteApp(appId):
    p_task(f"Deleting app with ID: {appId}...")
    try:
        AzCli(f"ad app delete --id {appId}")
        p_success("SUCCESS!")
    except:
        p_err("ERROR!", False)
        p_err(f"Failed to delete app! Try doing so manually through the Azure portal.", True)

    p_success("Successfully cleaned up GraphStrike!")   
    sys.exit()


def provision():
    global access_token
    # Check python3 version
    CheckVersion()
    
    # Check that dependencies are installed
    DepCheck("make", "make")
    DepCheck("nasm", "nasm")
    DepCheck("x86_64-w64-mingw32-gcc", "mingw-w64")

    p_task("Parsing Profile...")
    
    # Use these booleans to know when we have entered each section to trigger on the 'set uri' field within each
    bHttpGetBlock = False
    bHttpPostBlock = False
    with open('../graphstrike.profile', 'r') as f:
        for line in f:
            if "http-get" in line:
                bHttpGetBlock = True
            elif "http-post" in line:
                bHttpPostBlock = True

            if "set sleeptime" in line:
                sleepTime = re.search('"(.*)"', line).group(1)
            if "set uri" in line:
                if bHttpGetBlock:
                    httpGetPrefix = re.search('"/(.*)"', line).group(1)
                    bHttpGetBlock = False
                elif bHttpPostBlock:
                    httpPostPrefix = re.search('"/(.*)"', line).group(1)
                    bHttpPostBlock = False
    f.close()

    if sleepTime != None and bHttpGetBlock != None and bHttpPostBlock != None:
        p_success("SUCCESS!")
        p_info_plain(f"Found sleepTime: {sleepTime}")
        p_info_plain(f"Found httpGetPrefix: {httpGetPrefix}")
        p_info_plain(f"Found httpPostPrefix: {httpPostPrefix}")
    else:
        p_err("ERROR!", False)
        if sleepTime == None:
            p_err("Could not locate 'set sleeptime' value!", True)
        elif httpGetPrefix == None:
            p_err("Could not locate http-get block 'set uri' value!", True)
        elif httpPostPrefix == None:
               p_err("Could not locate http-post block 'set uri' value!", True)
        return     
    
    # Check and ensure that the cs-decrypt-metadata.py script as well as GraphStrike.py have execute permissions
    if not os.access(METADATA_SCRIPT, os.X_OK):
        st = os.stat(METADATA_SCRIPT)
        os.chmod(METADATA_SCRIPT, st.st_mode | stat.S_IEXEC)

    if not os.access(GRAPHSTRIKE_SCRIPT, os.X_OK):
        st = os.stat(GRAPHSTRIKE_SCRIPT)
        os.chmod(GRAPHSTRIKE_SCRIPT, st.st_mode | stat.S_IEXEC)      

    # Prompt user to enter cobaltstrike directory
    while True:
        csDir = input("\nEnter the absolute path of the cobaltstrike directory (e.g. /opt/cobaltstrike/): ")
        if not csDir.endswith('/'):
            csDir += '/'

        p_task("Checking Cobalt Strike directory...")
        if os.path.isfile(f"{csDir}teamserver"):
            p_success("SUCCESS!")
            break
        else:
            p_err("ERROR!", False)
            p_err(f"Cannot locate '{csDir}teamserver', check your path and try again", True)

    # Prompt user for tenant name and attempt to login to that tenant
    while True:
        tenant = input("\nEnter the full name of your tenant (e.g. mytenant.onmicrosoft.com | enter 'exit' to quit): ")
        if tenant == 'exit':
            return
        p_task(f"Signing into {tenant}...")
        try:
            response = AzCli(f"login --allow-no-subscriptions --tenant {tenant}")
            tenantId = response[0]['tenantId']
            p_success("SUCCESS!")
            break
        except:
            ""

    # p_task doesn't like newlines, so add one here to make it pretty...
    print("")

    # Create an app in the tenant
    p_task("Creating new app in Azure...")
    try:
        appId = AzCli(f"ad app create --display-name GraphStrike{str(random.randint(0,1000))} --required-resource-accesses @../inc/manifest.json --query appId").replace('"', '')
        p_success("SUCCESS!")
    except:
        p_err("Failed to create app in Azure.", True)
    
    # These next steps will fail unless we give Azure a little time to process the app creation...
    p_info_plain("\nSleeping for 30 seconds to allow app to be created in Azure...\n")
    while True:
        time.sleep(30)
        try:
            # Grant admin consent for assigned permissions
            p_task("Granting admin consent to requested API permissions...")
            AzCli(f"ad app permission admin-consent --id {appId}")
            p_success("SUCCESS!")
        except:
            p_err("ERROR!", False)
            p_err("Failed to grant admin consent to app in Azure.", False)
            DeleteApp(appId)

        try:
            # Create client secret
            p_task("Creating client secret that can be used to fetch access tokens...")
            clientSecret = AzCli(f"ad app credential reset --id {appId} --append --display-name creds --years 1 --query password").replace('"', '')
            p_success("SUCCESS!")
            break
        except:
            p_err("Hit exception trying to add client secret!", False)
            DeleteApp(appId)

    # Again we need to wait for the previous steps to be reflected before proceeding
    p_info_plain("\nSleeping for 30 seconds to allow added permissions to take effect...\n")
    while True:
        time.sleep(30)

        # Get an access token
        p_task("Fetching access token using new client secret...")
        access_token, refreshTime = GetAccessToken(appId, clientSecret, tenantId)

        if access_token == None:
            p_err("ERROR!", False)
            p_err(f"Exception fetching access token: {str(r.content)}", False)
            p_info_plain("\nSleeping 30 seconds and then trying again...\n")
        else:
            p_success("SUCCESS!")
            
            # Now resolve the siteId
            URL = "https://graph.microsoft.com/v1.0/sites/root"
            headers = {
                'Authorization':'Bearer ' + access_token
            }

            p_task("Retrieving Site ID...")
            r = requests.get(url = URL, headers = headers)

            #Parse output
            if "200" in str(r):
                data = r.json()
                siteId = data['id']
                p_success("SUCCESS!")
            elif "403" in str(r):
                p_err("ERROR!", False)
                p_err("Need to give Azure more time, sleeping for another 30...", False)
            else:
                p_err("ERROR!", False)
                p_err(f"Hit except fetching siteId! Data is: {str(r.content)}", False)
                p_info_plain("\nSleeping 30 seconds and then trying again...\n")

            if siteId != None:
                break
            else:
                p_info_plain("\nSleeping 30 seconds and then trying again...\n")

    # Only continue if we were successful in fetching an access token that has the active api permissions
    if siteId != None:

        # Now retrieve the driveId that we will be uploading files to
        URL = f"https://graph.microsoft.com/v1.0/sites/{siteId}/drives"
        headers = {
            'Authorization':'Bearer ' + access_token
        }
        while True:
            p_task("Retrieving Drive ID...")
            r = requests.get(url = URL, headers = headers)

            # Parse output
            if "200" in str(r):
                data = r.json()
                driveId = data['value'][0]['id']
                p_success("SUCCESS!")
                break
            else:
                p_err("ERROR!", False)
                p_err(f"Exception retrieving driveId: {str(r.content)}", False)
                time.sleep(1)

    # If we successfully fetched all of our values, we need to write out our config files and then compile the UDRL.
    if driveId != None:
        p_task("Writing UDRL config file...")
        cppHeader = f"""#include "include.h"

#define SHAREPOINT_ADDRESS C_PTR ( OFFSET ( "/v1.0/sites/{siteId}/drive" ) )
#define APP_CLIENT_ID C_PTR ( OFFSET ( "{appId}" ) )
#define APP_CLIENT_SECRET C_PTR ( OFFSET ( "{clientSecret}" ) )
#define TENANT_ID C_PTR ( OFFSET ( "{tenantId}" ) )
#define BID_DELIMITER C_PTR ( OFFSET ( "{bidDelimiter}") )
#define HTTP_GET_PREFIX C_PTR ( OFFSET ( "{httpGetPrefix}" ) )
#define HTTP_POST_PREFIX C_PTR ( OFFSET ( "{httpPostPrefix}" ) )"""

        # Write out UDRL config.h file
        with open('../GraphLdr/src/config.h', 'w+') as f:
            f.write(cppHeader)
        f.close()
        p_success("SUCCESS!")

        p_task("Writing GraphStrike server config file...")
        pythonHeader = f"""#!/usr/bin/python3

TENANT_ID = "{tenantId}"
CLIENT_ID = "{appId}"
CLIENT_SECRET = "{clientSecret}"
SITE_ID = "{siteId}"
DRIVE_ID = "{driveId}"
BID_DELIMITER = "{bidDelimiter}"
HTTP_GET_PREFIX = "{httpGetPrefix}"
HTTP_POST_PREFIX = "{httpPostPrefix}"
CS_DIR = "{csDir}" 
SLEEP_TIME = "{sleepTime}" """

        # Write out python server config.py file
        with open('../inc/config.py', 'w+') as f:
            f.write(pythonHeader)
        f.close()
        p_success("SUCCESS!")

        # Call make to compile UDRL
        p_task("Calling make to compile GraphLdr...")
        result = subprocess.run(['make', '-C', '../GraphLdr/'], capture_output = True, text = True)

        # Stderr returned anything, something went wrong. Abort.
        if len(result.stderr) > 0:
            p_err("ERROR!", False)
            p_err(result.stderr, False)
            DeleteApp(appId)
        else:
            p_success("SUCCESS!")

        p_success("Successfully configured and compiled GraphStrike!")
        p_info("Complete the rest of GraphStrike setup as instructed by the README.")

help = """

Usage: ./provisioner <mode>

Modes:
    new     Create a new Azure application and configure GraphStrike for use     
    delete  Delete an existing Azure application and remove any files created by GraphStrike in SharePoint
    
Hints:
    - You will need to sign in as a Global Admin of the tenant you are going to use for GraphStrike in order 
      for provisioning to succeed! This is required in order to grant Admin Consent for the 
      Sites.ReadWrite.All API permission we assign the created app.

    - The provisioner attempts to load and read the 'GraphStrike.profile' that comes included as part of 
      setup; you need to use this same profile with your Cobalt Strike team server!
"""

if __name__ == '__main__':

    print(BANNER)
    print("GraphStrike Provisioner\n")

    # Check python3 version
    CheckVersion()

    if len(sys.argv) > 1:
        command = sys.argv[1].lower()

        if command == "new":
            provision()

        elif command == "delete":
            p_info("Cleaning up!")
            
            # Get access token
            access_token, refreshTime = GetAccessToken()

            # Open config.py and read clientId var
            with open('../inc/config.py', 'r') as f:
                for line in f:
                    if "CLIENT_ID" in line:
                        appId = re.search('"(.*)"', line).group(1)
            f.close()

            # Delete any files remaining in SharePoint
            p_task("Deleting remaining SharePoint files...")
            driveItems = ListFiles(access_token)
            for entry in driveItems:
                DeleteFile(access_token, driveItems[entry]['id'])
            p_success("SUCCESS!")

            # Delete the config file and compiled UDRL locally
            p_task("Deleting GraphStrike generated artifacts...")
            try:
                os.remove('../inc/config.py')
                os.remove('../client/GraphLdr.x64.bin')
                p_success("SUCCESS!")
            except:
                p_err("ERROR!", False)
                p_err("Failed to delete inc/config.py and/or client/GraphLdr.x64.bin!", True)

            # Delete the app via az cli
            if appId != None:
                DeleteApp(appId)
        else:
            print(help)
    else:
        print(help)