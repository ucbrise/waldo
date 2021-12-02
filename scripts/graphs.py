# Natacha Crooks - ncrooks@berkeley.edu - 2020

# This is an example script that plots all graphs for a particular paper.
# This script  assumes that all experiments are located in expData, and
# makes use of the plotting library in graph_util

import shieldExperiment
import sys
sys.path.append("util/")
from ssh_util import *
from ec2_util import *
import boto.ec2
from compile_util import *
from prop_util import *
from math_util import *
from graph_util import *
import matplotlib
matplotlib.use('Agg')
import numpy as np
import matplotlib.pyplot as plt

# Script to plot all graphs. Needs to be updated when add new experiments

expData = "../experiments/results/current-results/"
plotTPC = False
plotSmallbank = False
plotFreeHealth = False
plotStrideDurability = False
plotCheckpointFrequency = True
plotParallelOram= True
plotStrideSize = True
plotWriteOpt = False
plotWriteBack= True
plotWriteBackStride = True
plotApplications = True
plotApplicationsSlides = True
plotBatchSucks = True

def aggregateDataThroughput(folder, dataPath, output,
        outputStd, legend = None):
    x = len(dataPath)
    y = len(dataPath[0])
    if (legend):
        dat = np.zeros((y,x+1))
        datStd = np.zeros((y,x+1))
        startIndex = 1
        for j in range(0,y):
            dat[j][0] = legend[j]
            datStd[j][0] = legend[j]
    else:
        dat = np.zeros((y,x))
        datStd = np.zeros((y,x))
        startIndex = 0
    for i in range(0,x):
       for j in range(0,y):
            name = folder + "/" + dataPath[i][j]
            print name
            data = np.atleast_2d(np.loadtxt(name))
            nbRepetitions =  data.shape[0]
            reps  = np.zeros(nbRepetitions)
            for r in range(0,nbRepetitions):
                print name
                reps[r] = (data[r][11])
            print nbRepetitions
            print reps
            dat[j][i+startIndex] = np.mean(reps)
            datStd[j][i+startIndex] = np.std(reps)
            print np.std(reps)
    np.savetxt(output, dat, delimiter=' ')
    np.savetxt(outputStd, datStd, delimiter=' ')

def measureIncrease(dataPath, output, legend = None):
 print "Measure Increase"
 data = np.atleast_2d(np.loadtxt(dataPath))
 print data
# What is changing is in a column
 nbRows =  data.shape[0]
 nbCols = data.shape[1]
 out= np.zeros((nbRows,nbCols))
 if (legend):
    index = 1
    for i in range(0, nbRows):
        out[i][0]=data[i][0]
 else:
    index = 0
 for j in range(index,nbCols):
    baseline = data[0][j]
    for k in range (1, nbRows):
       increase = data[k][j]/baseline
       out[k][j]=increase
 np.savetxt(output, out, delimiter=' ')




def aggregateDataLatency(folder, dataPath, output,
        outputStd, legend = None):
    x = len(dataPath)
    y = len(dataPath[0])
    if (legend):
        dat = np.zeros((y,x+1))
        datStd = np.zeros((y,x+1))
        startIndex = 1
        for j in range(0,y):
            dat[j][0] = legend[j]
            datStd[j][0] = legend[j]
    else:
        dat = np.zeros((y,x))
        datStd = np.zeros((y,x))
        startIndex = 0
    for i in range(0,x):
       for j in range(0,y):
            name = folder + "/" + dataPath[i][j]
            data = np.atleast_2d(np.loadtxt(name))
            nbRepetitions =  data.shape[0]
            reps  = np.zeros(nbRepetitions)
            for r in range(0,nbRepetitions):
                reps[r] = (data[r][1])
            dat[j][i+startIndex] = np.mean(reps)
            datStd[j][i+startIndex] = np.std(reps)
    np.savetxt(output, dat, delimiter=' ')
    np.savetxt(outputStd, datStd, delimiter=' ')

def main():
    print "Durability: # of Strides"
    if (plotStrideDurability):
        folder = expData + "/" + "oram/durability/nb-strides"
        outputThroughput = folder + "/aggT.dat"
        outputLatency = folder + "/aggL.dat"
        outputThroughputStd = folder + "/aggTStd.dat"
        outputLatencyStd = folder + "/aggLStd.dat"

        barNames = ["1", "2", "4", "6", "8"]
        datasetNames = ["Server NoDur", "Server Dur", "Dynamo NoDur", "Dynamo Dur" ]
        data = [
                [
                "oram-server-nb-stride-1-not-durable/results.dat",
    		"oram-server-nb-stride-2-not-durable/results.dat",
    		"oram-server-nb-stride-4-not-durable/results.dat",
    		"oram-server-nb-stride-6-not-durable/results.dat",
    		"oram-server-nb-stride-8-not-durable/results.dat",
                ],
                [
                "oram-server-nb-stride-1-durable/results.dat",
                "oram-server-nb-stride-2-durable/results.dat",
                "oram-server-nb-stride-4-durable/results.dat",
                "oram-server-nb-stride-6-durable/results.dat",
                "oram-server-nb-stride-8-durable/results.dat",
                ],
                [
                "oram-dynamo-nb-stride-1-not-durable/results.dat",
    		"oram-dynamo-nb-stride-2-not-durable/results.dat",
    		"oram-dynamo-nb-stride-4-not-durable/results.dat",
    		"oram-dynamo-nb-stride-6-not-durable/results.dat",
    		"oram-dynamo-nb-stride-8-not-durable/results.dat",
                ],
                [
                "oram-dynamo-nb-stride-1-durable/results.dat",
                "oram-dynamo-nb-stride-2-durable/results.dat",
                "oram-dynamo-nb-stride-4-durable/results.dat",
                "oram-dynamo-nb-stride-6-durable/results.dat",
                "oram-dynamo-nb-stride-8-durable/results.dat",
                ],
          ]
        aggregateDataThroughput(folder,data, outputThroughput, outputThroughputStd)
        aggregateDataLatency(folder,data, outputLatency, outputLatencyStd)
        dat = [(outputThroughput,0), (outputThroughput,1), (outputThroughput,2), (outputThroughput,3)]
        datStd = [(outputThroughputStd,0), (outputThroughputStd,1), (outputThroughputStd,2), (outputThroughputStd,3)]
        plotBars("Durability (# of Batches)", barNames, datasetNames,
                "Throughput (ops/s)", dat, True, folder + "/stride-durable-bars", datStd,
                black=False, ylim = 12000, xAxis='Number of Read Batches')
        dat = [(outputLatency,0), (outputLatency,1), (outputLatency,2), (outputLatency,3)]
        datStd = [(outputLatencyStd,0), (outputLatencyStd,1), (outputLatencyStd,2), (outputLatencyStd,3)]
        plotBars("Durability (# of Batches)", barNames, datasetNames,
                "Latency (ms)", dat, True, folder + "/stride-durable-latency-bars", datStd, black=False,
                xAxis='Number of Read Batches')

    print "Durability: Checkpoint Frequency"
    if (plotCheckpointFrequency):
        folder = expData + "/" + "oram/durability/checkpoint-freq"
        outputThroughput = folder + "/aggT.dat"
        outputLatency = folder + "/aggL.dat"
        outputThroughputStd = folder + "/aggTStd.dat"
        outputLatencyStd = folder + "/aggLStd.dat"

        barNames = ["1", "4", "16", "64", "256"]
        datasetNames = ["Server", "Server WAN", "Dynamo"]
        data = [
                [
                "oram-server-freq-1-durable/results.dat",
    		"oram-server-freq-4-durable/results.dat",
    		"oram-server-freq-16-durable/results.dat",
    		"oram-server-freq-64-durable/results.dat",
    		"oram-server-freq-256-durable/results.dat",
                ],
		[
                "oram-geoserver-freq-1-durable/results.dat",
    		"oram-geoserver-freq-4-durable/results.dat",
    		"oram-geoserver-freq-16-durable/results.dat",
    		"oram-geoserver-freq-64-durable/results.dat",
    		"oram-geoserver-freq-256-durable/results.dat",
                ],
                [
                "oram-dynamo-freq-1-durable/results.dat",
    		"oram-dynamo-freq-4-durable/results.dat",
    		"oram-dynamo-freq-16-durable/results.dat",
    		"oram-dynamo-freq-64-durable/results.dat",
    		"oram-dynamo-freq-256-durable/results.dat",
                ],

                ]
        aggregateDataThroughput(folder,data, outputThroughput, outputThroughputStd)
        aggregateDataLatency(folder,data, outputLatency, outputLatencyStd)
        dat = [(outputThroughput,0), (outputThroughput, 1), (outputThroughput,2)]
        datStd = [(outputThroughputStd,0), (outputThroughputStd,1), (outputThroughputStd,2)]
        plotBars("Durability (Checkpoint Frequency)", barNames, datasetNames,
                "Throughput (ops/s)", dat, True, folder + "/checkpoint-freq-throughput-bars", datStd,
                black=False,  ylim=8000)
        dat = [(outputLatency,0),(outputLatency,1), (outputLatency,2)]
        datStd = [(outputLatencyStd,0),(outputLatency,1), (outputLatency,2)]
        plotBars("Durability (Checkpoint Frequency)", barNames, datasetNames,
                "Latency (ms)", dat, True, folder + "/checkpoint-latency-bars", datStd, black=False,
                xAxis='Checkpoint Frequency')


##################### Parallelisation of the ORAM ###################################
    print "Parallel ORAM Results"
    if (plotParallelOram):
        folder = expData + "/" + "parallel-oram"
        outputThroughput = folder + "/aggT.dat"
        outputThroughputStd = folder + "aggTStd.dat"
        barNames = ["Dummy", "Server", "Server WAN", "Dynamo"]
        dataSetNames = ["Sequential", "Parallel", "ParallelCrypto"]
        data = [ # Sequential
                [
                    "base-oram-seq-dummy-nocrypto/results.dat",
                    "base-oram-seq-server-hashmap-nocrypto/results.dat",
                    "base-oram-seq-geoserver-hashmap-nocrypto/results.dat",
                    "base-oram-seq-dynamo-nocrypto/results.dat"],
                # Parallel No Crypto
                [
                    "base-oram-par-dummy-nocrypto/results.dat",
                    "base-oram-par-server-hashmap-nocrypto/results.dat",
                    "base-oram-par-geoserver-hashmap-nocrypto/results.dat",
                    "base-oram-par-dynamo-nocrypto/results.dat"
                 ],
                # Parallel
                [
                    "base-oram-par-dummy/results.dat",
                    "base-oram-par-server-hashmap/results.dat",
                    "base-oram-par-geoserver-hashmap/results.dat",
                    "base-oram-par-dynamo/results.dat"
                 ],
         ]
        aggregateDataThroughput(folder,data, outputThroughput, outputThroughputStd)
        dat = [(outputThroughput,0), (outputThroughput,1), (outputThroughput,2)]
        datStd = [(outputThroughputStd,0), (outputThroughputStd,1), (outputThroughputStd,2)]
        plotBars("Parallelisation - Throughput Impact", barNames, dataSetNames,
                "Throughput (ops/s)", dat, True, folder + "/parallel-oram-throughput", datStd,  True, black= False, logY=True)


####    ############## Impact of write optimisation #############################
    print "Write Optimisations"
    if (plotWriteOpt):
        folder = expData + "/" + "write-opt"
        outputThroughput = folder + "/aggT.dat"
        outputLatency = folder + "/aggL.dat"
        outputThroughputStd = folder + "/aggTStd.dat"
        outputLatencyStd = folder + "/aggLStd.dat"
        barNames = ["RO",
                "RH", "WH", "WO"]
        datasetNames = ["Dummy", "Dummy-Opt", "Server", "Server-Opt", "Dynamo", "Dynamo-Opt"]
        data = [ # Dummy
                [
                    "base-oram-par-dummy-rh/results.dat",
                    "base-oram-par-dummy-rh/results.dat",
                    "base-oram-par-dummy-wh/results.dat",
                    "base-oram-par-dummy-wo/results.dat",
                ],
                # Dummy Opt
                [
                    "base-oram-par-dummy-rh/results.dat",
                    "base-oram-par-dummy-rh-opt/results.dat",
                    "base-oram-par-dummy-wh-opt/results.dat",
                    "base-oram-par-dummy-wo-opt/results.dat",
                ],# Server
                [
                    "base-oram-par-server-rh/results.dat",
                    "base-oram-par-server-rh/results.dat",
                    "base-oram-par-server-wh/results.dat",
                    "base-oram-par-server-wo/results.dat",
                ],
                # Server Opt
                [
                    "base-oram-par-server-rh/results.dat",
                    "base-oram-par-server-rh-opt/results.dat",
                    "base-oram-par-server-wh-opt/results.dat",
                    "base-oram-par-server-wo-opt/results.dat",
                 ],
                [
                    "base-oram-par-dynamo-rh/results.dat",
                    "base-oram-par-dynamo-rh/results.dat",
                    "base-oram-par-dynamo-wh/results.dat",
                    "base-oram-par-dynamo-wo/results.dat",
                ],
                # Server Opt
                [
                    "base-oram-par-dynamo-rh/results.dat",
                    "base-oram-par-dynamo-rh-opt/results.dat",
                    "base-oram-par-dynamo-wh-opt/results.dat",
                    "base-oram-par-dynamo-wo-opt/results.dat",
                 ]
                 ]
        aggregateDataThroughput(folder,data, outputThroughput, outputThroughputStd)
        aggregateDataLatency(folder,data, outputLatency,outputLatencyStd)
        dat = [(outputThroughput,0), (outputThroughput,1), (outputThroughput,2), (outputThroughput,3), (outputThroughput,4), (outputThroughput,5)]
        datStd = [(outputThroughputStd,0), (outputThroughputStd,1), (outputThroughputStd,2), (outputThroughputStd,3), (outputThroughput,4), (outputThroughput,5)]
        plotBars("Write Optimisation", barNames, datasetNames,
               "Throughput (ops/s)", dat, False, folder + "/writes-throughput-bars", datStd, black=False)
####    ############## Impact of write back #############################
    print "Write Back"
    if (plotWriteBack):
        folder = expData + "/" + "writeback"
        outputThroughput = folder + "/aggT.dat"
        outputLatency = folder + "/aggL.dat"
        outputThroughputStd = folder + "/aggTStd.dat"
        outputLatencyStd = folder + "/aggLStd.dat"
        barNames = ["Dummy", "Server", "Server WAN", "Dynamo"]
        datasetNames = ["Normal", "Write Back"]
        data = [
                [
                    "base-oram-par-dummy/results.dat",
                    "base-oram-par-server-hashmap/results.dat",
                    "base-oram-par-geoserver-hashmap/results.dat",
                    "base-oram-par-dynamo/results.dat"
               ],
               [
                    "base-oram-par-dummy-writeback/results.dat",
                    "base-oram-par-server-hashmap-writeback/results.dat",
                    "base-oram-par-geoserver-hashmap-writeback/results.dat",
                    "base-oram-par-dynamo-writeback/results.dat",
               ]
        ]
        aggregateDataThroughput(folder,data, outputThroughput,outputThroughputStd)
        aggregateDataLatency(folder,data, outputLatency,outputLatencyStd)
        dat = [(outputThroughput,0), (outputThroughput,1)]
        datStd = [(outputThroughputStd,0), (outputThroughputStd,1)]
        plotBars("Delayed Write", barNames, datasetNames,
                "Throughput (ops/s)", dat, False, folder + "/writes-throughput-bars", datStd, black=False)
        dat = [(outputLatency,0), (outputLatency,1)]
        datStd = [(outputLatencyStd,0), (outputLatencyStd,1)]
        plotBars("Delayed Write", barNames, datasetNames,
                "Latency (ms)", dat, False, folder + "/writes-latency-bars", datStd, black=False)

####    ##################### Impact of stride size #######################################
    print "Batch Size Results"
    if (plotStrideSize):
        folder = expData + "/" + "strides"
        outputThroughput = folder + "/aggT.dat"
        outputLatency = folder + "/aggL.dat"
        outputThroughputStd = folder + "/aggTStd.dat"
        outputLatencyStd = folder + "/aggLStd.dat"
        xAxis = [1,
                10,100,
                500,1000,2000,5000,
                10000]
        barNames = [
                "1",
                "10","100",
                "500",
                "1000",
                "2000",
                "5000",
                "10000"]
        datasetNames = ["Dummy", "Server", "Server WAN", "Dynamo"]
        data = [ # Dummy
                [
                    "base-oram-par-dummy-1/results.dat",
                    "base-oram-par-dummy-10/results.dat",
                    "base-oram-par-dummy-100/results.dat",
                    "base-oram-par-dummy-500/results.dat",
                    "base-oram-par-dummy-1000/results.dat",
                    "base-oram-par-dummy-2000/results.dat",
                    "base-oram-par-dummy-5000/results.dat",
                    "base-oram-par-dummy-10000/results.dat"],
                # Server
                [
                    "base-oram-par-server-hashmap-1/results.dat",
                   "base-oram-par-server-hashmap-10/results.dat",
                    "base-oram-par-server-hashmap-100/results.dat",
                    "base-oram-par-server-hashmap-500/results.dat",
                    "base-oram-par-server-hashmap-1000/results.dat",
                    "base-oram-par-server-hashmap-2000/results.dat",
                    "base-oram-par-server-hashmap-5000/results.dat",
                    "base-oram-par-server-hashmap-10000/results.dat",
                 ],
                # Server WAN
                [
                    "base-oram-par-geoserver-hashmap-1/results.dat",
                   "base-oram-par-geoserver-hashmap-10/results.dat",
                    "base-oram-par-geoserver-hashmap-100/results.dat",
                    "base-oram-par-geoserver-hashmap-500/results.dat",
                    "base-oram-par-geoserver-hashmap-1000/results.dat",
                    "base-oram-par-geoserver-hashmap-2000/results.dat",
                    "base-oram-par-geoserver-hashmap-5000/results.dat",
                    "base-oram-par-geoserver-hashmap-10000/results.dat",
                 ],
                # Dynamo
                [
                    "base-oram-par-dynamo-1/results.dat",
                    "base-oram-par-dynamo-10/results.dat",
                   "base-oram-par-dynamo-100/results.dat",
                    "base-oram-par-dynamo-500/results.dat",
                    "base-oram-par-dynamo-1000/results.dat",
                    "base-oram-par-dynamo-2000/results.dat",
                    "base-oram-par-dynamo-5000/results.dat",
                    "base-oram-par-dynamo-10000/results.dat",
                 ],
        ]
        aggregateDataThroughput(folder,data, outputThroughput, outputThroughputStd, xAxis)
        aggregateDataLatency(folder,data, outputLatency, outputLatencyStd,xAxis)
        dat = [(outputThroughput,1), (outputThroughput,2), (outputThroughput,3), (outputThroughput,4)]
        datStd = [(outputThroughputStd,1), (outputThroughputStd,2), (outputThroughputStd,3), (outputThroughputStd,4)]
        plotBars("Batch Size - Throughput Impact", barNames, datasetNames,
                "Throughput (ops/s)", dat, True, folder + "/strides-throughput-bars", datStd, ylim = 14000, black=False)
        dat = [(outputLatency,1), (outputLatency,2), (outputLatency,3), (outputLatency,4)]
        datStd = [(outputLatencyStd,1), (outputLatencyStd,2), (outputLatencyStd,3), (outputLatencyStd,4)]
        plotBars("Batch Size - Latency Impact", barNames, datasetNames,
                "Latency (ms)", dat, True, folder + "/strides-latency-bars", datStd, black=False)
    print "WriteBack Batch Size Results"
    if (plotWriteBackStride):
        folder = expData + "/" + "writebackstrides"
        outputThroughput = folder + "/aggT.dat"
        outputLatency = folder + "/aggL.dat"
        outputThroughputStd = folder + "/aggTStd.dat"
        outputLatencyStd = folder + "/aggLStd.dat"
        xAxis = [1,
                2,4,
                6,8,
                #10,
                16, 32, 64,128,256,512]
        barNames = ["1",
                "2","4",
                "6",
                "8",
               # "10",
                "16", "32", "64", "128", "256", "512"]
        datasetNames = ["Dummy", "Server", "Server WAN", "Dynamo"]
        data = [ # Dummy
                [
                    "base-oram-par-dummy-1/results.dat",
                    "base-oram-par-dummy-2/results.dat",
                    "base-oram-par-dummy-4/results.dat",
                    "base-oram-par-dummy-6/results.dat",
                    "base-oram-par-dummy-8/results.dat",
                    #"base-oram-par-dummy-10/results.dat",
                    "base-oram-par-dummy-16/results.dat",
                    "base-oram-par-dummy-32/results.dat",
                    "base-oram-par-dummy-64/results.dat",
                    "base-oram-par-dummy-128/results.dat",
                    "base-oram-par-dummy-256/results.dat",
                    "base-oram-par-dummy-512/results.dat",
                   ],
                # Server
                [
                    "base-oram-par-server-hashmap-1/results.dat",
                    "base-oram-par-server-hashmap-2/results.dat",
                    "base-oram-par-server-hashmap-4/results.dat",
                    "base-oram-par-server-hashmap-6/results.dat",
                    "base-oram-par-server-hashmap-8/results.dat",
                    #"base-oram-par-server-hashmap-10/results.dat",
                    "base-oram-par-server-hashmap-16/results.dat",
                    "base-oram-par-server-hashmap-32/results.dat",
                    "base-oram-par-server-hashmap-64/results.dat",
                    "base-oram-par-server-hashmap-128/results.dat",
                    "base-oram-par-server-hashmap-256/results.dat",
                    "base-oram-par-server-hashmap-512/results.dat",
                   ],
                # Server WAN
                [
                    "base-oram-par-geoserver-hashmap-1/results.dat",
                    "base-oram-par-geoserver-hashmap-2/results.dat",
                    "base-oram-par-geoserver-hashmap-4/results.dat",
                    "base-oram-par-geoserver-hashmap-6/results.dat",
                    "base-oram-par-geoserver-hashmap-8/results.dat",
                    #"base-oram-par-geoserver-hashmap-10/results.dat",
                    "base-oram-par-geoserver-hashmap-16/results.dat",
                    "base-oram-par-geoserver-hashmap-32/results.dat",
                    "base-oram-par-geoserver-hashmap-64/results.dat",
                    "base-oram-par-geoserver-hashmap-128/results.dat",
                    "base-oram-par-geoserver-hashmap-256/results.dat",
                    "base-oram-par-geoserver-hashmap-512/results.dat",
                   ],
                # Dynamo
                [
                    "base-oram-par-dynamo-1/results.dat",
                    "base-oram-par-dynamo-2/results.dat",
                    "base-oram-par-dynamo-4/results.dat",
                    "base-oram-par-dynamo-6/results.dat",
                    "base-oram-par-dynamo-8/results.dat",
                    #"base-oram-par-dynamo-10/results.dat",
                    "base-oram-par-dynamo-16/results.dat",
                    "base-oram-par-dynamo-32/results.dat",
                    "base-oram-par-dynamo-64/results.dat",
                    "base-oram-par-dynamo-128/results.dat",
                    "base-oram-par-dynamo-256/results.dat",
                    "base-oram-par-dynamo-512/results.dat",
                    ],
        ]
        aggregateDataThroughput(folder,data, outputThroughput, outputThroughputStd, xAxis)
        aggregateDataLatency(folder,data, outputLatency, outputLatencyStd,xAxis)
        dat = [(outputThroughput,1), (outputThroughput,2), (outputThroughput,3), (outputThroughput,4)]
        datStd = [(outputThroughputStd,1), (outputThroughputStd,2), (outputThroughputStd,3), (outputThroughputStd,4)]
        plotBars("Number of Batches- Throughput Impact", barNames, datasetNames,
                "Throughput (ops/s)", dat, False, folder + "/writebackstrides-throughput-bars", datStd, ylim=15000,black=False)
        dat = [(outputLatency,1), (outputLatency,2), (outputLatency,3), (outputLatency,4)]
        datStd = [(outputLatencyStd,1), (outputLatencyStd,2), (outputLatencyStd,3), (outputLatencyStd,4)]
        plotBars("Number of Batches - Latency Impact", barNames, datasetNames,
                "Latency (ms)", dat, False, folder + "/writebackstrides-latency-bars", datStd, black=False)

    print "Write Back Batch Size Results Increase"
    if (plotWriteBackStride):
        folder = expData + "/" + "writebackstrides"
        outputIncrease= folder + "/increase.dat"
        xAxis = [1,
                2,4,
 #               6,
 8,
#10,
16,32,64,128,256,512
]
        barNames = ["1",
                "2","4",
#                "6",
                "8",
#                "10",
                "16","32","64","128",#"256","512"
                ]
        datasetNames = ["Dummy", "Server", "Server WAN", "Dynamo"]
        data = [ # Dummy
                [
                    "base-oram-par-dummy-1/results.dat",
                    "base-oram-par-dummy-2/results.dat",
                    "base-oram-par-dummy-4/results.dat",
                    "base-oram-par-dummy-8/results.dat",
                    "base-oram-par-dummy-16/results.dat",
                    "base-oram-par-dummy-32/results.dat",
                    "base-oram-par-dummy-64/results.dat",
                    "base-oram-par-dummy-128/results.dat",
               #     "base-oram-par-dummy-256/results.dat",
               #     "base-oram-par-dummy-512/results.dat",
                ],
                # Server
                [
                    "base-oram-par-server-hashmap-1/results.dat",
                    "base-oram-par-server-hashmap-2/results.dat",
                    "base-oram-par-server-hashmap-4/results.dat",
                    "base-oram-par-server-hashmap-8/results.dat",
                    "base-oram-par-server-hashmap-16/results.dat",
                    "base-oram-par-server-hashmap-32/results.dat",
                    "base-oram-par-server-hashmap-64/results.dat",
                    "base-oram-par-server-hashmap-128/results.dat",
               #     "base-oram-par-server-hashmap-256/results.dat",
               #     "base-oram-par-server-hashmap-512/results.dat",
               ],
               # Geo Server
                [
                    "base-oram-par-geoserver-hashmap-1/results.dat",
                    "base-oram-par-geoserver-hashmap-2/results.dat",
                    "base-oram-par-geoserver-hashmap-4/results.dat",
                    "base-oram-par-geoserver-hashmap-8/results.dat",
                    "base-oram-par-geoserver-hashmap-16/results.dat",
                    "base-oram-par-geoserver-hashmap-32/results.dat",
                    "base-oram-par-geoserver-hashmap-64/results.dat",
                    "base-oram-par-geoserver-hashmap-128/results.dat",
               #     "base-oram-par-geoserver-hashmap-256/results.dat",
               #     "base-oram-par-geoserver-hashmap-512/results.dat",
               ],
               # Dynamo
                [
                    "base-oram-par-dynamo-1/results.dat",
                    "base-oram-par-dynamo-2/results.dat",
                    "base-oram-par-dynamo-4/results.dat",
#                    "base-oram-par-dynamo-6/results.dat",
                    "base-oram-par-dynamo-8/results.dat",
#                    "base-oram-par-dynamo-10/results.dat",
                    "base-oram-par-dynamo-16/results.dat",
                    "base-oram-par-dynamo-32/results.dat",
                    "base-oram-par-dynamo-64/results.dat",
                    "base-oram-par-dynamo-128/results.dat",
               #     "base-oram-par-dynamo-256/results.dat",
               #     "base-oram-par-dynamo-512/results.dat",
             ],
        ]
        aggregateDataThroughput(folder,data, outputThroughput, outputThroughputStd, xAxis)
        measureIncrease(outputThroughput, outputIncrease, xAxis)
        outputIncrease= folder + "/increase.dat"
        dat = [(outputIncrease,"Dummy",0,1), (outputIncrease,"Server",0,2), (outputIncrease, "Server WAN", 0,3),(outputIncrease,"Dynamo",0,4)]
        print "FOlder " + folder
        plotLine("Number of Batches - Throughput Increase",
        "Batch Size", "Relative Increase", folder + "/writebackstrides-increase-line", dat, True, log2X=True)
#        dat = [(outputIncrease,1), (outputIncrease,2), (outputIncrease,3)]
#        plotBars("Number of Batches - Throughput Increase", barNames, datasetNames,
#                "Ratio", dat, True, folder + "/writebackstrides-increase-bars",  black=True, paper=True,xHor=True)
    if (plotApplications):
        folder = expData + "/" + "applications"
        outputThroughput = folder + "/aggT.dat"
        outputLatency = folder + "/aggL.dat"
        outputThroughputStd = folder + "/aggTStd.dat"
        outputLatencyStd = folder + "/aggLStd.dat"
        barNames = ["TPC-C","FreeHealth",  "Smallbank"]
        datasetNames = ["Obladi", "NoPriv", "MySQL", "ObladiW", "NoPrivW"]
        data = [ # Obladi
                [
                    "tpcc/tpc10oramserverhashmap/results.dat",
                    "freehealth/freehealthoramserverhashmap/results.dat",
                    "smallbank/smallbankoramserverhashmap/results.dat"
                   ],
                # NoPriv
                [
                    "tpcc/tpc10noramserverhashmap/results.dat",
                    "freehealth/freehealthnoramserverhashmap/results.dat",
                    "smallbank/smallbanknoramserverhashmap/results.dat"
               ],

               # Mysql
                [
                    "tpcc/tpc10norammysql/results.dat",
                    "freehealth/freehealthsql/results.dat",
                    "smallbank/smallbanknoramsql/results.dat"
               ],

                # Obladi WAN
                [
                    "tpcc/tpc10oramgeoserverhashmap/results.dat",
                    "freehealth/freehealthoramgeoserverhashmap/results.dat",
                    "smallbank/smallbankoramgeoserverhashmap/results.dat"
               ],

                # NoPriv WAN
                [
                    "tpcc/tpc10noramgeoserverhashmap/results.dat",
                    "freehealth/freehealthnoramgeoserverhashmap/results.dat",
                    "smallbank/smallbanknoramgeoserverhashmap/results.dat"
               ]
        ]
        aggregateDataThroughput(folder,data, outputThroughput, outputThroughputStd)
        aggregateDataLatency(folder,data, outputLatency, outputLatencyStd)
        dat = [(outputThroughput,0), (outputThroughput,1), (outputThroughput, 2), (outputThroughput,3), (outputThroughput,4)]
        datStd = [(outputThroughputStd,0), (outputThroughputStd,1), (outputThroughputStd,2), (outputThroughputStd,3), (outputThroughputStd,4)]
        plotBars("Plot", barNames, datasetNames,
                "Throughput (Trx/s)", dat, False, folder + "/application-throughput-bars", datStd, logY=True,  black=False)
        dat = [(outputLatency,0), (outputLatency,1), (outputLatency,2), (outputLatency,3), (outputLatency,4)]
        datStd = [(outputLatencyStd,0), (outputLatencyStd,1), (outputLatencyStd,2), (outputLatencyStd,3), (outputLatencyStd,4)]
        plotBars("Plot", barNames, datasetNames,
                "Latency (ms)", dat, False, folder + "/application-latency-bars", datStd,  logY=True,black=False)
    if (plotApplicationsSlides):
        folder = expData + "/" + "applications"
        outputThroughput = folder + "/aggTSlides.dat"
        outputLatency = folder + "/aggLSlides.dat"
        outputThroughputStd = folder + "/aggTSlidesStd.dat"
        outputLatencyStd = folder + "/aggLSlidesStd.dat"
        barNames = ["TPC-C","FreeHealth",  "Smallbank"]
        datasetNames = ["Obladi", "NoPriv", "MySQL"]
        data = [

                              # Obladi WAN
                [
                    "tpcc/tpc10oramgeoserverhashmap/results.dat",
                    "freehealth/freehealthoramgeoserverhashmap/results.dat",
                    "smallbank/smallbankoramgeoserverhashmap/results.dat"
               ],

                # NoPriv WAN
                [
                    "tpcc/tpc10noramgeoserverhashmap/results.dat",
                    "freehealth/freehealthnoramgeoserverhashmap/results.dat",
                    "smallbank/smallbanknoramgeoserverhashmap/results.dat"],
               # Mysql
                [
                    "tpcc/tpc10norammysql/results.dat",
                    "freehealth/freehealthsql/results.dat",
                    "smallbank/smallbanknoramsql/results.dat"
               ],


        ]
        aggregateDataThroughput(folder,data, outputThroughput, outputThroughputStd)
        aggregateDataLatency(folder,data, outputLatency, outputLatencyStd)
        dat = [(outputThroughput,0), (outputThroughput,1), (outputThroughput, 2)]
        datStd = [(outputThroughputStd,0), (outputThroughputStd,1), (outputThroughputStd,2)]
        plotBars("Plot", barNames, datasetNames,
                "Throughput (Trx/s)", dat, False, folder + "/application-throughput-bars-slides", datStd, logY=True,  black=False)
        dat = [(outputLatency,0), (outputLatency,1), (outputLatency,2)]
        datStd = [(outputLatencyStd,0), (outputLatencyStd,1), (outputLatencyStd,2)]
        plotBars("Plot", barNames, datasetNames,
                "Latency (ms)", dat, False, folder + "/application-latency-bars-slides", datStd,  logY=True,black=False)


    if (plotBatchSucks):
        folder = expData + "/applications/" + "smallbank"
        smallbankstride = folder + "/strides.dat"
        folder = expData + "/applications/" + "freehealth"
        freehealthstride = folder + "/strides.dat"
        folder = expData + "/applications/" + "tpcc"
        tpcstride = folder + "/strides.dat"
        dat = [(smallbankstride,"SmallBank",0,1), (freehealthstride,"FreeHealth",0,1), (tpcstride, "TPC-C",0,1)]
        plotLine("","Epoch Size (ms) ",
        "Throughput (trx/s)", folder + "/smallbank", dat, True)






















if __name__ == "__main__": main()
