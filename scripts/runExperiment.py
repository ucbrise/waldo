import argparse
import os
import os.path
import sys
import datetime
import time
import math

sys.path.append("util/")


from ssh_util import *
from azure_util import *
from prop_util import *
from math_util import *
from graph_util import *

clientPrefix = "client-"
serverPrefix = "server-"

PROPERTY_FILE = "config/tree_malicious_throughput.json"
CLIENT_CONFIG_FILE = "config/client.config"
SERVER_CONFIG_FILE = "config/server.config"
SSH_CONFIG_FILE = "config/ssh_config"

az = AzureSetup("scalable_oram")

def setupExperiment(propFile):
    properties = loadPropertyFile(propFile)
    # Username for ssh-ing.
    username = properties['username']
    # Name of the experiment that will be run
    experimentName = properties['experiment_name']
    # Project dir on the local machine
    localProjectDir = properties['local_project_dir']
    localSrcDir = properties["local_src_dir"]
    # Project dir on the remote machine
    remoteProjectDir = properties['remote_project_dir']
    # Source directory on the local machine (for compilation)
    localSrcDir = properties['local_src_dir']
    sshKeyFile = properties["ssh_key_file"]
    gitOrigin = properties["git_origin"]

    # The experiment folder is generated with the following path:
    # results/experimentName/Date
    # The date is used to distinguish multiple runs of the same experiment
    expFolder = '/results/' + experimentName
    expDir =  expFolder + "/" + datetime.datetime.now().strftime("%Y:%m:%d:%H:%M") + "/"
    properties['experiment_dir'] = expDir

    # LocalPath and RemotePath describe where data will be stored on the remote machine
    # and on the local machine
    localPath = localProjectDir + '/' + expDir + "/"
    remotePath = remoteProjectDir + '/' + expDir + "/"

    # Config files for each
    clientConfig = loadPropertyFile(CLIENT_CONFIG_FILE)
    serverConfig = loadPropertyFile(SERVER_CONFIG_FILE)

    clientConfig["addrs"] = [addr + ":12345" for addr in properties["server_ips"]]
    clientConfig["experiment_dir"] = properties["experiment_dir"]
    with open(CLIENT_CONFIG_FILE, 'w') as fp:
        json.dump(clientConfig, fp, indent = 2, sort_keys=True)
 
    serverConfig["port"] = "12345"
    serverConfig["addrs"] = [addr + ":12345" for addr in properties["server_ips"]]
    with open(SERVER_CONFIG_FILE, 'w') as fp:
        json.dump(serverConfig, fp, indent = 2, sort_keys=True)
 
    # Generate exp directory on all machines
    for client_ip in properties["client_ips"]:
        mkdirRemote(properties["username"], client_ip, remotePath, properties["ssh_key_file"])
    for server_ip in properties["server_ips"]:
        mkdirRemote(properties["username"], server_ip, remotePath, properties["ssh_key_file"])
    # Send configs
    sendFileHosts(SERVER_CONFIG_FILE, properties["username"], properties["server_ips"], remotePath, properties["ssh_key_file"])

    sendFileHosts(CLIENT_CONFIG_FILE, properties["username"], properties["client_ips"], remotePath, properties["ssh_key_file"])

    with open(propFile, 'w') as fp:
        json.dump(properties, fp, indent = 2, sort_keys=True)


def runExperiment(propFile):
    properties = loadPropertyFile(propFile)
    # Username for ssh-ing.
    user = properties['username']
    # Name of the experiment that will be run
    experimentName = properties['experiment_name']
    # Project dir on the local machine
    localProjectDir = properties['local_project_dir']
    # Project dir on the remote machine
    remoteProjectDir = properties['remote_project_dir']
    # Source directory on the local machine (for compilation)
    localSrcDir = properties['local_src_dir']
    expDir = properties['experiment_dir']
    remoteExpDir = remoteProjectDir + "/" + expDir
    localExpDir = localProjectDir + "/" + expDir
    logFolders = properties['log_folder']
    sshKey = properties["ssh_key_file"]
    username = properties["username"]
    clientIpList = properties["client_ips"]
    serverIpList = properties["server_ips"]

    # The nbclients field is a list that contains a list of client counts.
    # Ex, if this is listed: [1,2,4,8], the framework will run the experiment
    # 4 times: one with 1 clients, then with two, then four, then 8. The
    # format for collecting the data will be remoteExpDir/clientcount.
    nbRounds = len(properties['nbclients'])
    # number of times each experiment will be run
    nbRepetitions = properties['nbrepetitions']

    first = True
    dataLoaded = False

    for serverIp in serverIpList:
        executeRemoteCommand(username + "@" + serverIp, "pkill -f query_server", sshKey)

    # Run for each round, nbRepetitions time.
    for nbClients in properties['nbclients']:
        for nbConds in properties['nbconds']:
            for nbWindowSz in properties['nbwindowsz']:
                for nbNumBuckets in properties['nbnumbuckets']:
                    for it in range(0, nbRepetitions):
                        print("Number of clients " + str(nbClients))
                        print("Window size " + str(nbWindowSz))
                        print("Num buckets " + str(nbNumBuckets))
                        # Creates underlying file structure: remoteExpDir/1_1 for example for repetition 1 of round 1
                        roundName = str(nbClients) + "_" + str(nbConds) + "_" + str(nbWindowSz) + "_" + str(nbNumBuckets) + "_" + str(it)
                        localRoundFolder = localExpDir + "/" + roundName 
                        remoteRoundFolder = remoteExpDir + "/" + roundName 
                        print("Round Folder : " + str(localRoundFolder))
                        localPath = localRoundFolder
                        remotePath = remoteRoundFolder
                        print("Remote Path :" + str(remotePath))
                        executeCommand("mkdir -p " + localPath)
                        logFolder = remotePath + "/" + logFolders
                        properties['log_folder'] = logFolder
                        localProp = localPath + "/properties"
                        remoteProp = remotePath + "/properties"
                        print("Local properties path: " + localProp)
                        executeCommand("mkdir -p " + localProp)
                        properties['exp_dir'] = remotePath

                        for c in clientIpList:
                            mkdirRemote(username, c, remotePath, sshKey)
                            mkdirRemote(username, c, remoteProp, sshKey)
                            mkdirRemote(username, c, logFolder, sshKey)

                        for s in serverIpList:
                            mkdirRemote(username, s, remotePath, sshKey)
                            mkdirRemote(username, s, remoteProp, sshKey)
                            mkdirRemote(username, s, logFolder, sshKey)

                        # Generate a specific property file for each client/proxy/storage

                        # Start server
                        for j in range(3):
                            serverIp = serverIpList[j]
                            print "Starting server " + str(j)
                            file_id = serverIp + "_" + str(j)
                            localProp_ = localProp + "/server" + str(j) + ".config"
                            remoteProp_ = remoteProp + "/server" + str(j) + ".config"

                            serverConfig = loadPropertyFile(SERVER_CONFIG_FILE)
                            serverConfig["server_num"] = j
                            serverConfig["malicious"] = properties["malicious"]
                            serverConfig["cores"] = properties["cores"] / nbConds
                            if properties["query_type"] == "range" or properties["query_type"] == "range-throughput":
                                serverConfig["cores"] = serverConfig["cores"] / 2
                            with open(localProp_, 'w+') as fp:
                                json.dump(serverConfig, fp, indent = 2, sort_keys=True)
                            sendFile(localProp_, serverIp, username, remoteProp_, sshKey)
 
                            cmd = "cd dorydb; ./build/bin/query_server " + remoteProp_ + " 1> " + remotePath + "/server_" + file_id + ".log 2> " + remotePath + "/server_err_" + file_id + ".log"
                            t = executeNonBlockingRemoteCommand(username + "@" + serverIp, cmd, sshKey)
                            t.start()

                        time.sleep(20)

                        clientList = list()
                        for j in range(nbClients):
                            clientIp = clientIpList[j]
                            print "Starting client " + str(j)
                            file_id = clientIp + "_" + str(j)
                            localProp_ = localProp + "/client" + str(j) + ".config"
                            remoteProp_ = remoteProp + "/client" + str(j) + ".config"

                            clientConfig = loadPropertyFile(CLIENT_CONFIG_FILE)
                            clientConfig["run_name"] = remotePath + "/" + str(j) + "_" + properties["run_name"]
                            clientConfig["experiment_dir"] = remoteRoundFolder;
                            clientConfig["log_window_sz"] = nbWindowSz
                            clientConfig["log_num_buckets"] = nbNumBuckets
                            clientConfig["num_searches"] = properties["num_searches"]
                            clientConfig["num_appends"] = properties["num_appends"]
                            clientConfig["seconds"] = properties["seconds"]
                            clientConfig["reps"] = properties["reps"]
                            clientConfig["query_type"] = properties["query_type"]
                            clientConfig["malicious"] = properties["malicious"]
                            clientConfig["num_ands"] = nbConds
                            clientConfig["depth"] = nbWindowSz
                            with open(localProp_, 'w+') as fp:
                                json.dump(clientConfig, fp, indent = 2, sort_keys=True)
                            sendFile(localProp_, clientIp, username, remoteProp_, sshKey)
 
                            # Already copied the correct config files
                            cmd = "cd dorydb; ./build/bin/bench " + remoteProp_ + " 1>" + remotePath + "/client_" + file_id + ".log 2> " + remotePath + "/client_err_" + file_id + ".log"
                            t = executeNonBlockingRemoteCommand(username + "@" + clientIp, cmd, sshKey)
                            clientList.append(t)

                            # client needs to output tx count, latency pairs

                        print("Starting clients")
                        #time.sleep(10)
                        for t in clientList:
                            t.start()
                        # Wait for all clients to finish
                        for t in clientList:
                            t.join(9600)
          
                        collectData(propFile, localPath, remotePath)
                        print("Finished round")
                        print("--------------")

                        for serverIp in serverIpList:
                            executeRemoteCommand(username + "@" + serverIp, "pkill -f query_server", sshKey)
                        calculateParallel(propFile, localPath, roundName, nbClients, nbWindowSz, nbNumBuckets)
#        except Exception as e:
#            print " "
#        except subprocess.CalledProcessError, e:
#	    print str(e.returncode)

    return "Done with experiment"

def collectData(propFile, localFolder, remoteFolder):
    print("Collect data")
    properties = loadPropertyFile(propFile)
    sshKey = properties["ssh_key_file"]
    username = properties["username"]
    clientIpList = properties["client_ips"]
    serverIpList = properties["server_ips"]

    getDirectory(localFolder, username, clientIpList, remoteFolder, sshKey)
    getDirectory(localFolder, username, serverIpList, remoteFolder, sshKey)

# Computes experiment results and outputs all results in results.dat
# For each round in an experiment run the "generateData" method as a separate
# thread
def calculateParallel(propertyFile, localExpDir, roundName, numClients, windowSz, numBuckets):
    print("Calculating results")
    properties = loadPropertyFile(propertyFile)
    if not properties:
        print("Empty property file, failing")
        return
    experimentName = properties['experiment_name']
    if (not localExpDir):
            localProjectDir = properties['local_project_dir']
            expDir = properties['experiment_dir']
            localExpDir = localProjectDir + "/" + expDir
    print("Writing results to " + localExpDir + "/processed_results.dat")
    fileHandler = open(localExpDir + "/processed_results.dat", "w+")
    time = int(properties['exp_sec'])
    results = dict()
    #try:
    file_list = []
    
    print("Reading from file: " + localExpDir + "/" + roundName + "/results.dat")
    generateData(results, localExpDir + "/" + roundName + "/results.dat", 1, properties["seconds"])
    #except:
    #    print "No results file found"

    print("Finished Processing Batch")
           #executingThreads = list()
    sortedKeys = sorted(results.keys())
    for key in sortedKeys:
        fileHandler.write(results[key])
    fileHandler.flush()
    fileHandler.close()
    print("Finished collecting data")

# Generates data using the math functions available in math_util
# Expects latency to be in the third column of the output file
def generateData(results,folderName, clients, time):
    print("Generating Data for " + folderName)
    result = str(computeMean(folderName,1)) + " "
    result+= str(computeMin(folderName,1)) + " "
    result+= str(computeMax(folderName,1)) + " "
    result+= str(computeVar(folderName,1)) + " "
    result+= str(computeStd(folderName,1)) + " "
    result+= str(computePercentile(folderName,1,50)) + " "
    result+= str(computePercentile(folderName,1,75)) + " "
    result+= str(computePercentile(folderName,1,90)) + " "
    result+= str(computePercentile(folderName,1,95)) + " "
    result+= str(computePercentile(folderName,1,99)) + " " 
    print("Generated data for up through 99 percentile")
    result+= str(computeThroughput(folderName,1,time,1))
    results[clients]=result

def summarizeData(propertyFile):
    properties = loadPropertyFile(propertyFile)
    if not properties:
        print("Empty property file, failing")
        return
    expDir = properties['experiment_dir']
    localProjectDir = properties['local_project_dir']
    localExpDir = localProjectDir + "/" + expDir
    outFile = localExpDir + "/final_results.dat"
    fFinal = open(outFile, "w")
    nbRounds = len(properties['nbclients'])
    nbRepetitions = properties['nbrepetitions']
    for nbClients in properties['nbclients']:
        for nbConds in properties['nbconds']:
            for nbWindowSz in properties['nbwindowsz']:
                for nbNumBuckets in properties['nbnumbuckets']:
                    for it in range(0, nbRepetitions):
                        localRoundFolder = localExpDir + "/" + str(nbClients) + "_" + str(nbConds) + "_" + str(nbWindowSz) + "_" + str(nbNumBuckets) + "_" + str(it)
                        roundResults = localRoundFolder + "/processed_results.dat"
                        fRound = open(roundResults, "r")
                        fFinal.write(str(nbClients) + " " + str(nbConds) + " " + str(nbWindowSz) + " " + str(nbNumBuckets) +  " " + str(it) + " " + fRound.readline() + "\n")
                        fRound.close()
    fFinal.close()
 

def main():
    parser = argparse.ArgumentParser(description='Run experiment.')
    parser.add_argument('-s', '--setup', action='store_true',
                        help='setup instances (default: false)')
    parser.add_argument('-r', '--run', action='store_true',
                        help='run experiment (default: false)')
    args = parser.parse_args()

    if not args.provision and not args.setup and not args.run and not args.cleanup:
        parser.print_help()
        parser.exit()

    if args.setup:
        print("Setting up...")
        setupExperiment(PROPERTY_FILE)
    if args.run:
        print("Running experiment...")
        runExperiment(PROPERTY_FILE)
        summarizeData(PROPERTY_FILE)


if __name__ == '__main__':
    main()

