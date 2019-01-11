# Multiple_Hash_Scan

This is a portable script written in Python (Python 2.7) used for "Multiple Hash Scan" on VirusTotal. you can upload mutilple hashes (MD5, Sha1, Sha256) on VirusTotal. This supported wherever python is installed (Tested on Linux, Windows). User must have an input.txt file to upload which contains the hash values and based on that it'll scan the given hashes on VirusTotal and will generate two outputs (VT_Scan.txt, MD5.txt).

VT_Scan.txt: will stored the Hit counts for the hash value and how many AV is detected by malicious with the respectively name of malware.

EG: - Sophos = detected: True, version:4.98.0, result:Mal/Generic-S, update:20160621                                                            

MD5.txt: will stored only the MD5 hash value of given hahses.

This script scan 4 hash at the same time and take hold for 1 minute then it'll scan next four hashes and continue till the last hash.

# Pre-Requesites

- Internet Connection
- requests module (pip install requests)
- Python 2.7

# Usage

python HashScan.py

# Example

You have to enter your VirusTotal API Key at on 10th nuber row.

key = '' # Enter Your Virus Total API key

+++++++++++++++++++++++++++++++++++
+ Author:- Shilpesh Trivedi       +
+ Title :- Multiple Hash Scanning +

+++++++++++++++++++++++++++++++++++
 
 
 # Output (Output.csv)
 
 ![alt text](https://github.com/ShilpeshTrivedi/Multiple_Hash_Scan/blob/master/HashScan.png)
        

*************************************************************************************************************************************
