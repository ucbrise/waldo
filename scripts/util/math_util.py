### Natacha Crooks - UC Berkeley - 2020
### Contains utility functions related to processing output data
############################################

# Important functions include
# computeMean()
# computeThroughput()
# computeMedian()
# computeStd()
# computePercentile()


import os
#import scipy as sp
import numpy as np
import sys

# Return a list of file names in directory 'dir_name'
# If 'subdir' is true , recursively access subdirectories
# under dir_name
# Additional arguments, if any, are file extensions to add to the list.
#    Example usage: fileList = dir_list(r'H:\TEMP', False, 'txt', 'py', 'dat', 'log', 'jpg')
def dirList(dir_name, subdir, *args):
    fileList = []
    for file in os.listdir(dir_name):
        dirfile = os.path.join(dir_name, file)
        if os.path.isfile(dirfile):
            if len(args) == 0:
                fileList.append(dirfile)
            else:
                if os.path.splitext(dirfile)[1][1:] in args:
                    fileList.append(dirfile)
        # recursively access file names in subdirectories
        elif os.path.isdir(dirfile) and subdir:
            # print "Accessing directory:", dirfile
            fileList += dirList(dirfile, subdir, *args)
    return fileList


# Concatenates a file list to fn
def combineFiles(fileList, fn):
    f = open(fn, "w")
    for file in fileList:
     f.write(open(file).read())
    f.close()

def sort(data,colId):
    dat = data[data[:,colId].argsort()]
    return dat

### Dumps NP array to file
def printNpArray(output, data):
 with open(output, 'w') as text:
  col_length = data.shape[0]
  row_length = data.shape[1]
  print col_length
  print row_length
  for i in range(0,col_length):
   for j in range (0,row_length):
    text.write(" " + str(data[i,j]))
   text.write("\n")

# Divides appropriate column in the array by the
# specified constant. Useful for
def divide(inputArray,colID,constant):
    rows = inputArray[colID]
    for i in range(0,rows):
     inputArray[i,colID]=input[i,colID]/constant

# Multiplies appropriate column in the array by the
# specified constant. Useful for
def divide(inputArray,colID,constant):
    rows = inputArray[colID]
    for i in range(0,rows):
     inputArray[i,colID]=input[i,colID]*constant

# Computes average of a file for a given column
def computeMean(fi, colID):
 try:
  data_ = np.loadtxt(fi)
  data = np.atleast_2d(data_)
  mean = np.mean(data[:,colID])
  return mean
 except Exception as err:
  print str(err) + " " + fi
  print "Could not compute the mean"
  return 0

# Computes min of a file for a given column
def computeMin(fi, colID):
 try:
  data_ = np.loadtxt(fi)
  data = np.atleast_2d(data_)
  min = np.amin(data[:,colID])
  return min
 except Exception as e:
  print e
  return 1


# Computes min of a file for a given column
def computeMedian(fi, colID):
 try:
  data_ = np.loadtxt(fi)
  data = np.atleast_2d(data_)
  med = np.median(data[:,colID])
  return med
 except Exception as e:
  print e
  print "Error: fail to compute med"
  return 1


# Computes max of a file for a given column
def computeMax(fi, colID):
 try:
  data_ = np.loadtxt(fi)
  data = np.atleast_2d(data_)
  return np.amax(data[:,colID])
 except:
  print "Error: fail to compute max"
  return 0


# Computes var of a file for a given column
def computeVar(fi, colID):
 try:
  data_ = np.loadtxt(fi)
  data = np.atleast_2d(data_)
  return np.var(data[:,colID])
 except:
  print "Error: fail to compute variance"
  return 0


# Computes std of a file for a given column
def computeStd(fi, colID):
 try:
  data_ = np.loadtxt(fi)
  data = np.atleast_2d(data_)
  return np.std(data[:,colID])
 except:
  print "Error: fail to compute std"
  return 0


# Computes n percentile of a file for a given column
def computePercentile(fi, colID, percentile):
 try:
  data_ = np.loadtxt(fi)
  data = np.atleast_2d(data_)
  return np.percentile(data[:,colID], percentile)
 except:
  print "Error: fail to compute percentile"
  return 0


# Compute throughput for a file
# This function assumes that the
# number of lines denotes the number
# of transactions, and that the
# last entry in colID denotes elapsed
# time
def computeThroughput(fi, colID, time, batchSz):
 try:
  data = np.loadtxt(fi)
  col_length = data.shape[0]
  if (not time):
	elapsed = data[(col_length-1),colID] - data[0,colID]
  else:
	elapsed = time
  throughput = float(col_length)/float(elapsed)*float(batchSz)
  return throughput
 except:
  print "Error: fail to compute percentile"
  return 0
