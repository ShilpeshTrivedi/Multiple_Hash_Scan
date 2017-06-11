# Multiple_Hash_Scan

This is a portable script written in python used for "Multiple Hash Scan" on VirusTotal. you can upload mutilple hashes (MD5, Sha1, Sha256) on VirusTotal. This supported wherever python is installed (Tested on Linux, Windows). User must have an input.txt file to upload which contains the hash values and based on that it'll scan the given hashes on VirusTotal and will generate two outputs (VT_Scan.txt, MD5.txt).

VT_Scan.txt: will stored the Hit counts for the hash value and how many AV is detected by malicious with the respectively name of malware.

EG: -

Sophos = detected: True, version:4.98.0, result:Mal/Generic-S, update:20160621                                                              
McAfee = detected: True, version:6.0.6.653, result:Artemis!0002D20A7423, update:20160621                                                    
.                                                                                                                                           
.                                                                                                                                           
Baidu = detected: False, version:1.0.0.2, result: None, update:20160621                                                                                      
.                                                                                                                                           
.                                                                                                                                           
Symantec = detected: True, version:20151.1.1.4, result:Trojan.Malcol, update:20160621                                                            

MD5.txt: will stored only the MD5 hash value of given hahses.

This script scan 4 hash at the same time and take hold for 1 minute then it'll scan next four hashes and continue till the last hash.

# Pre-Requesites (Only for Windows OS)
Install the following libraries: requests, pefile and pywin32.

pip install -r requirements.txt

# Usage

python HashScan.py
