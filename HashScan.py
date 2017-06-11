import requests
import time

try :
        fp = open ('input.txt') # Here entered input file
except IOError:
        print "\n\nOops!!! 'input.txt' IS NOT FOUND IN SAME FOLDER"
        exit()

key = '' # Enter Your Virus Total API key

print '\n'
print ' +++++++++++++++++++++++++++++++++++'
print ' + Copyright :- Shilpesh Trivedi   +'
print ' + Title :- Multiple Hash Scanning +'
print ' +++++++++++++++++++++++++++++++++++'
print '\n'


try:
        for i, fyl in enumerate(fp):
                if i%4==0:
# Virus Total Analysis
                        if len(key) == 64: # Cheking For API Key
                                try:
                                        params = {'apikey': key, 'resource': fyl}
                                        url = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
                                        json_response = url.json()
                    
                                        response = int(json_response.get('response_code'))

                                        if response == 0:
                                                print '\n'
                                                print (' [-] '  + fyl + ' is not in Virus Total')
                                
                                        elif response == 1:
                                                positives = int(json_response.get('positives'))

                                                if positives == 0:
                                                        print '\n'
                                                        print (' [-] ' + fyl + ' is not malicious')
                                                else:
                                                        md5 = json_response.get('md5')
                                                        positives= int(json_response.get('positives'))
                                                        total= int(json_response.get('total'))
                                                        scans=str(json_response.get('scans'))
                        
                                                        print '\n [*] Malware Hit Count ' + str(positives) +'/'+str(total)
                                                        print '\n [*] ' + fyl + ' IS MALICIOUS'
                                                        print '\n [*] MD5 Value is = ' + md5
                                                        file = open('VT_Scan.txt','a')
                                                        file.write('Malware Hit Count ' + str(positives) +'/'+str(total))
                                                        file.write('\n\n')
                                                        file.write('MD5 Value is = ' + md5)
                                                        file.write('\n\n')
                                                        file.write(str(scans).replace('}, u','\n').replace(' u','').replace('{','').replace(': u',' = ').replace("'","").replace('}}','').replace(',',', '))
                                                        file.write('\n')
                                                        file.write('\n*************************************************************************************************************************************')    
                                                        file.write('\n')
                                                        file.close()

                                                        file= open('MD5.txt','a')
                                                        file.write(md5)
                                                        file.write('\n')
                                                        file.close()
                                        else:
                                                print fyl + ' [-] could not be searched. Please try again later.'
            
                                except Exception, e:
                                        print '\n [-] Oops!!, Somthing Wrong Check Your Internet Connection Or Entered Hash'
                        else:
                                print " [-] There is something Wrong With Your API Key."
                                exit()
                        time.sleep(60) # Here Used Time Sleep mathod here i used 40 sec mex
            
                else:
# Virus Total Analysis
                        if len(key) == 64: # Cheking For API Key
                                try:
                                        params = {'apikey': key, 'resource': fyl}
                                        url = requests.get('https://www.virustotal.com/vtapi/v2/file/report', params=params)
                                        json_response = url.json()
                    
                                        response = int(json_response.get('response_code'))

                                        if response == 0:
                                                print '\n'
                                                print (' [-] '  + fyl + ' is not in Virus Total')
                                
                                        elif response == 1:
                                                positives = int(json_response.get('positives'))

                                                if positives == 0:
                                                        print '\n'
                                                        print (' [-] ' + fyl + ' is not malicious')
                                                else:
                                                        md5 = json_response.get('md5')
                                                        positives= int(json_response.get('positives'))
                                                        total= int(json_response.get('total'))
                                                        scans=str(json_response.get('scans'))
                        
                                                        print '\n [*] Malware Hit Count ' + str(positives) +'/'+str(total)                                         
                                                        print '\n [*] ' + fyl + ' IS MALICIOUS'
                                                        print '\n [*] MD5 Value is = ' + md5
                                                        file = open('output.txt','a')
                                                        file.write('Malware Hit Count ' + str(positives) +'/'+str(total))
                                                        file.write('\n\n')
                                                        file.write('MD5 Value is = ' + md5)
                                                        file.write('\n\n')
                                                        file.write(str(scans).replace('}, u','\n').replace(' u','').replace('{','').replace(': u',' = ').replace("'","").replace('}}',''))
                                                        file.write('\n')
                                                        file.write('\n*************************************************************************************************************************************')    
                                                        file.write('\n')
                                                        file.close()

                                                        file= open('MD5.txt','a')
                                                        file.write(md5)
                                                        file.write('\n')
                                                        file.close()
                                        else:
                                                print fyl + ' [-] could not be searched. Please try again later.'
            
                                except Exception, e:
                                        print '\n [-] Oops!!, Somthing Wrong Check Your Internet Connection Or Entered Hash'
                        else:
                                print " [-] There is something Wrong With Your API Key."
                                exit()
except KeyboardInterrupt:
        print "\n\n Oops!!! PEROGRAM HALTED B'COZ YOU PRESS CTRL+C. "
