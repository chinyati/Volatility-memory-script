# Volatility memory analysis script

A python script to analyse a memory dump using Volaitility framework. The script will:
1. Search for operating system profile,
2. Find the running processes,
3. List the open and accessed network connections at memory capture,
4. Analyse image for malicious processes and DLLs

## Getting Started

* Clone/Download the repository
* Download the volatility executable for Windows or Linux and place them in project folder.
* Go to config.ini file and setup the volatility Installation path and also the location for the memory images as well as folder to save the outputs.

## How it works
This is a python script hence the system/container should have python and pip installed and running. Below is a sample of how script works:

![First Image](https://github.com/chinyati/malware-Script/blob/master/images/1.png)
![Second Image](https://github.com/chinyati/malware-Script/blob/master/images/2.png)]
![Third Image](https://github.com/chinyati/malware-Script/blob/master/images/3.png)]


## Usage
```
usage: python malscript.py -f [memory_image.dd]
```

## Improvements

1.	A More interactive interface so that user clearly interact with volatility using maybe a Web interface.
2.	Save the output formatted for JSOn or CSV so as to be able to analyse with other tools
