# Multiple_Hash_Scan

This is a portable script written in Python (Python 2.7) used for "Multiple Hash Scan" on VirusTotal. you can upload mutilple hashes (MD5, Sha1, Sha256) on VirusTotal. This supported wherever python is installed (Tested on Linux, Windows). User must have an input.txt file to upload which contains the hash values and based on that it'll scan the given hashes on VirusTotal and will generate two outputs (VT_Scan.txt, MD5.txt).

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

# Usage

python HashScan.py

# Example

You have to enter your VirusTotal API Key at on 10th nuber row.

key = ' ' # Enter Your Virus Total API key

+++++++++++++++++++++++++++++++++                                                                                                       
 Copyright :- Shilpesh Trivedi             
 Title :- Multiple Hash Scanning  
+++++++++++++++++++++++++++++++++
 
 [*] Malware Hit Count 44/56

 [*] 1a8add5b9ec54912a6ba4b06c39b8d2100034b48dddb5b717481935c292ad2ef  IS MALICIOUS

 [*] MD5 Value is = 0002d20a7423518b7f371302014076c9
 
