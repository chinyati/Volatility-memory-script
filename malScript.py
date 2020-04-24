#!/usr/bin/python

#IMPORT STATEMENTS FOR LIBRARIES AND GLOBAL VALUES
import re
import configparser
import os,shutil,sys
import argparse
import configparser

################################################################################
#Configuration file with Volatility installation path, Memory Image and Save location
config = configparser.ConfigParser()
config.read("config.ini")

#Defining constants and getting feeder values from config file
VOLATILITY_INSTALLATION = config.get('DEFAULT', 'vol_installation')
VOLATILITY_IMAGE = config.get('DEFAULT', 'vol_image')
SAVE_LOCATION = config.get('DEFAULT', 'save_contents')

#################################################################################
#Main Menu function, this is where the main activities are selected
def mainMenu():
    print ("\n--------------------------------------------------------------------------------")
    print ("1. Find The Image's Operating System Profile")
    print ("2. See The Running Processes")
    print ("3. Analyse The Image For Any Malicious Processes")
    print ("4. Check the Network connections")
    print ("5. Quit")
    print ("--------------------------------------------------------------------------------")
    while True:
        try:
            selection=int(input("Enter choice: "))
            if selection==1:
                profileImage()
                break
            elif selection==2:
                runningProcesses()
                break
            elif selection==3:
                malFind()
                break
            elif selection==4:
                netCheck()
                break
            else:
                print("Invalid choice. Enter 1-4")
                mainMenu()
        except ValueError:
                print("Something went wrong. Enter 1-4")
    exit

#################################################################################
#Function to read the Memory image and find its Operating system profile
def readMemoryImage(filename):
    #Define object to handle the output for the values found for image profile. Below script greps for a certain string
    imageProfile = os.popen(VOLATILITY_INSTALLATION + " -f " + VOLATILITY_IMAGE +
    " imageinfo 2>/dev/null | grep \"Suggested Profile(s)\" | awk '{print $4 $5 $6}'").read()

    #Stripped the string retrieved above
    imageProfile = imageProfile.rstrip()
    imageProfiles = imageProfile.split(",")
    #Now checking in volatility to see if the profile image has any running processes, if yes save that one
    for imageProfile in imageProfiles:
        profileCheck =  os.popen(VOLATILITY_INSTALLATION + " -f " + VOLATILITY_IMAGE +  " --profile="
        + imageProfile + " pslist 2>/dev/null").read()
        if "Offset" in profileCheck:
            return imageProfile
        return ""

#################################################################################
#Function to show output of profile
def profileImage():
    #Output of the readMemoryImage function computation
    sys.stdout.write("\n### Analysing Memory Image... " + VOLATILITY_IMAGE + "\n")
    sys.stdout.flush()

    sys.stdout.write("### Image Profile is.... ")
    sys.stdout.flush()

    #Used the volProfile object with the volatility image instantiated within the readMemoryImage function call
    imageProfile = readMemoryImage(VOLATILITY_IMAGE)
    sys.stdout.write(">>> " + imageProfile + "\n")
    sys.stdout.flush()

    #Call for mainMenu to return after execution
    mainMenu()

#################################################################################
#Function to list all processes and listed on a tree
def runningProcesses():

    sys.stdout.write("\n### Retrieving processes on memory... " + VOLATILITY_IMAGE)
    sys.stdout.flush()

    sys.stdout.write("\n### SAVING the Process Tree output to processTree.txt \n" + SAVE_LOCATION + "\n \n")
    sys.stdout.flush()

    #pstree script as would be intiated within VOlatility
    processList = os.popen(VOLATILITY_INSTALLATION + " -f " + VOLATILITY_IMAGE +  " pstree" + "\n 2>/dev/pstree.").read()

    #Saving to text terminal output to text file
    pstree = SAVE_LOCATION + "processTREE.txt"
    with open(pstree, "w") as text:
        text.write(processList)

    sys.stdout.write(processList)
    sys.stdout.flush()

    mainMenu()

#################################################################################
#Function to find malware infected processes
def malFind():

    sys.stdout.write("\n### Analysing the memory image for malicious processes... \n" + VOLATILITY_IMAGE + "\n")
    sys.stdout.flush()

    #malfind script as would be run in within volatility whilst restricting terminal output
    malwareDetection = os.popen(VOLATILITY_INSTALLATION + " -f " + VOLATILITY_IMAGE +  " malfind 2>/dev/null").read()

    sys.stdout.write("\n### SAVING the Malfind output to MALFIND.txt \n" + SAVE_LOCATION + "\n")
    sys.stdout.flush()

    #Saving terminal output to text file
    malfind = SAVE_LOCATION + "MALFIND.txt"
    with open(malfind, "w") as text:               #Open MALFIND.txt as write
        text.write(malwareDetection)

    sys.stdout.write("\n### Now outputting the MALICIOUS processes and their IDs \n \n")
    sys.stdout.flush()

    #USE the re.match to find the Process tag and print out the output of corrupt services
    with open('MALFIND.txt', 'r') as findProc: #Open MALFIND.txt as read
        #Create macliciousProcess text file to write the matching process output
        maliciousProcess = SAVE_LOCATION + "maliciousProcess.txt"
        with open(maliciousProcess, "w") as text1:
            for executable in findProc:
                if re.match("Process", executable):
                    #Write the malicious processes to text file
                    text1.write(executable)
                    print(executable)

    mainMenu()

#################################################################################
#Function to find malware infected processes
def netCheck():
    sys.stdout.write("\n### Checking the network connections accessed on... \n" + VOLATILITY_IMAGE + "\n")
    sys.stdout.flush()

    sys.stdout.write("\n### SAVING the network scan output to networkScan.txt \n" + SAVE_LOCATION + "\n")
    sys.stdout.flush()

    sys.stdout.write("\n### Now outputting the NETWORK scan output \n \n")
    sys.stdout.flush()

    #connscan script as would be run within volatility whilst restricting terminal outputting
    networkScan = os.popen(VOLATILITY_INSTALLATION + " -f " + VOLATILITY_IMAGE +  " connscan" + "\n 2>/dev/null").read()

    #Saving terminal output to text file
    network = SAVE_LOCATION + "networkScan.txt"
    with open(network, "w") as text:
        text.write(networkScan)

    print (networkScan)
    with open('networkScan.txt', 'r') as findNet: #Open MALFIND.txt as read
        for address in findNet:
            if re.match("Process", address):
                print(address)

    mainMenu()

#################################################################################
#End of file arguments
args = argparse.ArgumentParser()
args.add_argument("-f", "--imagefile", required=True, help="Cridex Memory image")
args = vars(args.parse_args())

mainMenu()
#################################################################################
