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
 
 # OUTPUT (VT_Scan.txt)
 
Malware Hit Count 44/56

MD5 Value is = 0002d20a7423518b7f371302014076c9

uBkav = detected: True, version:1.3.0.8042, result:W32.Clod562.Trojan.0c8e, update:20160620
ahnlab = detected: True, version:3.7.4.14563, result:Trojan/Win32.RMC_v10.N355774191, update:20160621
MicroWorld-eScan = detected: True, version:12.0.250.0, result:DoS.Rmc.1.0, update:20160621
nProtect = detected: True, version:2016-06-21.01, result:Trojan/W32.DoS.51200.B, update:20160621
CMC = detected: True, version:1.1.0.977, result:DoS.Win32.Rmc!O, update:20160620
CAT-QuickHeal = detected: False, version:14.00, result: None, update:20160621
ALYac = detected: True, version:1.0.1.9, result:DoS.Rmc.1.0, update:20160621
Malwarebytes = detected: False, version:2.1.1.1115, result: None, update:20160621
VIPRE = detected: True, version:50286, result:Trojan.Win32.Generic!BT, update:20160621
AegisLab = detected: True, version:4.2, result:DoS.W32.Rmc.10!c, update:20160621
TheHacker = detected: True, version:6.8.0.5.961, result:Trojan/Hami, update:20160620
BitDefender = detected: True, version:7.2, result:DoS.Rmc.1.0, update:20160621
K7GW = detected: True, version:9.230.19993, result:Riskware ( 0040eff71 ), update:20160621
K7AntiVirus = detected: True, version:9.230.19993, result:Riskware ( 0040eff71 ), update:20160621
Baidu = detected: False, version:1.0.0.2, result: None, update:20160621
F-Prot = detected: False, version:4.7.1.166, result: None, update:20160621
Symantec = detected: True, version:20151.1.1.4, result:Trojan.Malcol, update:20160621
ESET-NOD32 = detected: False, version:13681, result: None, update:20160621
TrendMicro-HouseCall = detected: True, version:9.800.0.1009, result:DDOS_RMC.10, update:20160621
Avast = detected: True, version:8.0.1489.320, result:Win32:Malware-gen, update:20160621
ClamAV = detected: True, version:0.98.5.0, result:Win.Trojan.Agent-371784, update:20160621
Kaspersky = detected: True, version:15.0.1.13, result:DoS.Win32.Rmc.10, update:20160621
Alibaba = detected: False, version:1.0, result: None, update:20160621
NANO-Antivirus = detected: True, version:1.0.38.8881, result:Trojan.Win32.Rmc.dcjcjn, update:20160621
ViRobot = detected: True, version:2014.3.20.0, result:Trojan.Win32.S.Agent.51200.RJ[h], update:20160621
Ad-Aware = detected: True, version:3.0.3.794, result:DoS.Rmc.1.0, update:20160621
Sophos = detected: True, version:4.98.0, result:Mal/Generic-S, update:20160621
Comodo = detected: True, version:25300, result:UnclassifiedMalware, update:20160621
F-Secure = detected: True, version:11.0.19100.45, result:DoS.Rmc.1.0, update:20160621
DrWeb = detected: True, version:7.0.18.3140, result:DDoS.RMC.10, update:20160621
Zillya = detected: True, version:2.0.0.2923, result:Tool.Rmc.Win32.3, update:20160620
TrendMicro = detected: True, version:9.740.0.1012, result:DDOS_RMC.10, update:20160621
McAfee-GW-Edition = detected: True, version:v2015, result:BehavesLike.Win32.Trojan.qc, update:20160621
Emsisoft = detected: True, version:3.5.0.656, result:DoS.Rmc.1.0 (B), update:20160621
Cyren = detected: False, version:5.4.16.7, result: None, update:20160621
Jiangmin = detected: True, version:16.0.100, result:Hacktool.Rmcont, update:20160621
Avira = detected: True, version:8.3.3.4, result:TR/Rmc.DoS.10, update:20160621
Fortinet = detected: True, version:5.4.233.0, result:W32/Rmc.10!dos, update:20160621
Antiy-AVL = detected: True, version:1.0.0.1, result:HackTool[DoS]/DoS.Win32, update:20160621
Kingsoft = detected: False, version:2013.8.14.323, result: None, update:20160621
Arcabit = detected: True, version:1.0.0.741, result:DoS.Rmc.1.0, update:20160621
SUPERAntiSpyware = detected: False, version:5.6.0.1032, result: None, update:20160621
Microsoft = detected: True, version:1.1.12805.0, result:DoS:Win32/Rmc.1_0, update:20160621
TotalDefense = detected: False, version:37.1.62.1, result: None, update:20160621
McAfee = detected: True, version:6.0.6.653, result:Artemis!0002D20A7423, update:20160621
AVware = detected: True, version:1.5.0.42, result:Trojan.Win32.Generic!BT, update:20160621
VBA32 = detected: True, version:3.12.26.4, result:Trojan.VBRA.012588, update:20160621
Baidu-International = detected: True, version:3.5.1.41473, result:Trojan.Win32.Rmc.10, update:20160614
Zoner = detected: False, version:1.0, result: None, update:20160621
Tencent = detected: True, version:1.0.0.1, result:Win32.Trojan.Rmc.C, update:20160621
Yandex = detected: True, version:5.5.1.3, result:DoS.Rmc!2Oq96CxFO0U, update:20160621
Ikarus = detected: True, version:T3.2.1.6.0, result:DoS.Win32.Rmc, update:20160621
GData = detected: True, version:25, result:DoS.Rmc.1.0, update:20160621
AVG = detected: True, version:16.0.0.4604, result:DoS.CI, update:20160621
Panda = detected: False, version:4.6.4.2, result: None, update:20160620
Qihoo-360 = detected: True, version:1.0.0.1120, result:Win32/Trojan.DoS.4a9, update:20160621

*************************************************************************************************************************************
