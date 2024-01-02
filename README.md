# GraphStrike
![gscolor](https://github.com/RedSiege/GraphStrike/assets/152210699/adee8da9-b712-4dc5-b9c5-a32798338ee8)

Release blog: [GraphStrike: Using Microsoft Graph API to Make Beacon Traffic Disappear](https://redsiege.com/blog/2024/01/graphstrike-release)  
Developer blog: [GraphStrike: Anatomy of Offensive Tool Development](https://redsiege.com/blog/2024/01/graphstrike-developer)

## Introduction
GraphStrike is a suite of tools that enables Cobalt Strike's HTTPS Beacon to use [Microsoft Graph API](https://learn.microsoft.com/en-us/graph/use-the-api) for C2 communications. All Beacon traffic will be transmitted via two files created in the attacker's SharePoint site, and all communications from Beacon will route to https://graph.microsoft.com:

![image](https://github.com/RedSiege/GraphStrike/assets/152210699/ddb744d0-93dd-4791-9f5e-3f0f2dfd65bb)

GraphStrike includes a provisioner to create the required Azure assets for Cobalt Strike HTTPS over Graph API:

![image](https://github.com/RedSiege/GraphStrike/assets/152210699/a5d777d6-deb2-4640-a394-1bde0b51bdc8)

**GraphStrike does not create any paid assets in Azure, so no additional cost is incurred by the use of GraphStrike or it's provisioner.**

### Why?
Threat intelligence has been released regarding several different APTs leveraging Microsoft Graph API and other Microsoft services for offensive campaigns:  
1. [BLUELIGHT - APT37/InkySquid/ScarCruft](https://www.volexity.com/blog/2021/08/17/north-korean-apt-inkysquid-infects-victims-using-browser-exploits/)  
2. [Graphite - APT28/Fancy Bear](https://malpedia.caad.fkie.fraunhofer.de/details/win.graphite)  
3. [Graphican - APT15/Nickel/The Flea](https://symantec-enterprise-blogs.security.com/blogs/threat-intelligence/flea-backdoor-microsoft-graph-apt15)  
4. [SiestaGraph - UNKNOWN](https://www.elastic.co/security-labs/siestagraph-new-implant-uncovered-in-asean-member-foreign-ministry)  

Threat actors continue to leverage legitimate services for illegitimate purposes. Utilizing a high-reputation domain like graph.microsoft.com for C2 communications is extremely effective and desirable, but often complicated and prohibitive from a time and effort standpoint. Most C2 frameworks do not support methods to fetch or rotate access tokens, which makes them unable to use Graph API. This can make it difficult for red teams to replicate these techniques, and deprives defenders of a chance to observe and develop signatures for this kind of activity. GraphStrike seeks to ease that burden and provide a reliable and repeatable process to leverage Microsoft Graph API while keeping the familiarity and reliability of the Cobalt Strike user experience.

### Is this an External C2?
Not technically, no. Having previously built a true [External C2 using Graph API](https://github.com/Octoberfest7/Presentations/blob/main/TradecraftCON_2022/Teams_CobaltStrike_External_C2.pdf) (which sent Beacon traffic as Microsoft Teams messages), the burden of having to develop, maintain, and integrate a custom implant that meets the External C2 specification and gets the job done is all too familiar. GraphStrike instead leverages an open source [User Defined Reflective Loader](https://www.cobaltstrike.com/product/features/user-defined-reflective-loader)(UDRL) called [AceLdr](https://github.com/kyleavery/AceLdr/tree/main) by Kyle Avery (adapted as 'GraphLdr' in this project) to hook the WinINet library calls that Beacon normally makes and manipulate them as neccessary in order to use Graph API. There is no custom implant or additional process to speak of, just the Beacon process with a couple of hooked Windows API's. On the server side there is a Python3 program that translates Cobalt Strike Team Server traffic into Graph API traffic and vice-versa.

# Features
GraphStrike supports almost all normal Cobalt Strike activities to include:  
1. Use of Proxychains through a Cobalt Strike SOCKS proxy (though it is very slow...)  
2. Upload/Download of large files  
3. BOFs, execute-assembly, etc.  

This also includes GraphStrike integration of the sleep, exit, and remove commands to match GraphStrike Server sleep times with Beacon as well as delete files in SharePoint when a Beacon is exited or removed.  

GraphStrike additionally incorporates all of the features and functionality of the original AceLdr, with some additional API's made to utilize call stack spoofing as well.  

# Requirements
GraphStrike requires the following before you get started:  
1. A Microsoft Azure tenant with a SharePoint/O365 license assigned + site created. The default site is fine.
2. An Azure account with Global Administrator permissions in that tenant.  
3. Python 3.8-3.11<sup>[Note #4](#notes)</sup> (and additional dependencies that will be installed during the setup process)

## Firewall rules
1. Ensure that each machine that the Cobalt Strike client runs on is able to connect to the Cobalt Strike team server machine on ports 443 and 5000.  

# Setup
Make note of the following before proceeding with the setup process:  

**1. Certain components utilize relative paths to locate other assets. Please change directories as instructed below.**  
**2. The Cobalt Strike profile may only be edited BEFORE step 5 in the below setup process<sup>[Note #1](#notes)</sup>.**  

### On the machine that will run the Cobalt Strike team server:
1.  Clone the repo.
2.  From the repo directory, run ```sudo setup/install_dependencies.sh``` to install required system dependencies.  
3.  Run ```python3 -m venv virtual``` and then ```source virtual/bin/activate``` to create and then enter the virtual environment.  
4.  Change to the setup directory and run ```pip3 install -r requirements.txt```.  
5.  Run ```./provisioner.py new``` and complete the setup process.  
6.  Start the Cobalt Strike team server using graphstrike.profile as the malleable C2 profile.  
7.  Start a Cobalt Strike client instance (you can do this on a client machine, or on the TS box and kill it afterwards) and create a Cobalt Strike HTTPS listener on port 443 with ```graph.microsoft.com``` as the HTTPS Hosts and HTTPS Host(Stager) fields.
8.  Change back to the primary repo directory and run the GraphStrike Server using ```./GraphStrike.py```.

### On ALL machines that will run the Cobalt Strike client:
9.  Copy the GraphStrike/client directory to the client machine from the TS machine. **This must be done only AFTER completing provisioning!**
10. Import GraphStrike.cna to Cobalt Strike using the Script Manager.  
11. Create Cobalt Strike payloads, whether that be raw shellcode or compiled artifacts using the Artifact Kit or an alternate payload generation framework. **Artifact Kit users see below!**   
12. Profit.

### Artifact Kit Users
Due to the size of GraphLdr, users of the Artifact Kit will need to re-compile it with specific options in order for GraphStrike to be compatible with Artifact Kit generated payloads. Specifically, the 'Stage Size' and 'RDLL Size' fields need to be specified so as to use the 100K RDLL size. Two examples of working syntax are provided below:  

```./build.sh pipe VirtualAlloc 505029 100 false false none /opt/cobaltstrike/artifacts```  
```./build.sh peek HeapAlloc 492376 100 false true indirect /opt/cobaltstrike/artifacts```

# Cleanup

### On the machine that is running the TS + GraphStrike Server:
1. Stop the GraphStrike server
2. Change back to the setup directory and run ```./provisioner.py delete``` to remove created Azure assets.

# Notes
In no particular order, here are a few suggestions and observations to help use GraphStrike to it's full potential.  
1. The profile included with GraphStrike is very minimalistic; this is by design. **Changing any of the EXISTING fields in the profile may/will break GraphStrike!** You should be able to add additional profile language/behaviour to other sections that are not already defined (.e.g customize pipe name, injection behaviour, etc). **Any edits to the profile MUST be made prior to running the provisioner!**
2. The Azure application that is used for C2 communications by both Beacon and the GraphStrike Server is rate-limited to 1200 requests/min. The GraphStrike Server uses 120/min as a baseline to function. The lower a Beacon's sleep time is the more requests it will make; additionally, each Beacon created using GraphStrike is going to be using some of that 1200/min limit. Going interactive with a Beacon is doable, but going interactive with more than one Beacon probably isn't. If you run into rate limiting issues, consider increasing the sleep time for your beacons, decreasing the number of Beacon's you have running, or both.  
3. While the GraphStrike Server's sleep time changes on a per-Beacon basis according to issued sleep commands, what this really means is that the GraphStrike Server will sleep for the specified time before checking in with the TS for tasking. It does NOT mean that Beacon will immediately receive and process the tasking as soon as it is retrieved from the TS by the GraphStrike server. Beacon will sleep the specified time before reaching out to SharePoint to retrieve TS tasking, but due to the nature of async C2 this will not be in lockstep with when the GraphStrike Server uploads it.  
4. If a Beacon dies without having exited gracefully (AV, it crashes, etc), the Beacon will **appear** to still be calling into the TS, and the fact that it is dead will only become apparent once you issue it a command. What is really connecting to the TS / making it appear that the Beacon is still calling in is the GraphStrike server, so this really isn't a reflection on the health of a Beacon. Such is the nature of async C2.  
5. GraphStrike works on a 1:1:1 model; 1 SharePoint site is associated with 1 GraphStrike server which is associated with 1 TS. You'll have issues if you try connecting two TS/GraphStrike servers to a single SharePoint site. You can of course connect multiple Cobalt Strike clients to a single TS / GraphStrike server, each client just needs a copy of the 'client' folder produced by the provisioning process.  
6. There is a [known issue](https://github.com/Azure/azure-cli/issues/27673) regarding compatibility of the az utility used by GraphStrike and Python 3.12.  
7. I'd recommend you review the documentation for [AceLdr](https://github.com/kyleavery/AceLdr/tree/main), as all of the notes from that project apply here as well.  

# Limitations
The following limitations exist in GraphStrike:  
1. Only x64 Beacons are supported.
2. Staged Beacons are not supported.
3. GraphStrike is only compatible with the WinINet library; the new WinHTTP library option for Beacons is not supported.
4. No support for issuing a sleep command via Beacon's right-click menu. Sleep beacons using the command line option instead.
5. GraphStrike is only supported on Linux instances of Cobalt Strike. Windows support is certainly possible to implement, and is really just a matter of changing around some paths within the Python files and Aggressor script.

# Credits
GraphStrike would not be possible without the contributions of the following individuals:  
1. Kyle Avery for [AceLdr](https://github.com/kyleavery/AceLdr/tree/main)  
2. Didier Stevens for [cs-decrypt-metadata.py](https://github.com/DidierStevens/DidierStevensSuite/blob/master/cs-decrypt-metadata.py)
3. Mike Saunders, Corey Overstreet, Chris Truncer, and Justin Palk from the Red Siege team who all kindly beta tested GraphStrike and identified multiple issues that were fixed prior to release.
