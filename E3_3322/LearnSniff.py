from scapy.all import *
from datetime import datetime
import time
import csv

start = time.time()
srcMACData={}
srcIPData={}
dstMACData={}
dstIPData={}

out=open("out.csv",'a',encoding='utf-8')
csv_write = csv.writer(out)
for i in range(100):
    dpkt = sniff(count=1)
    current_time=datetime.now()
    try:
        srcMAC=dpkt[0].src
        dstMAC=dpkt[0].dst
        srcIP=dpkt[0][IP].src
        dstIP=dpkt[0][IP].dst
        length=dpkt[0].len
        if srcMAC not in srcMACData.keys():
            srcMACData[srcMAC]=0
        if srcIP not in srcIPData.keys():
            srcIPData[srcIP]=0
        if dstMAC not in dstMACData.keys():
            dstMACData[dstMAC]=0
        if dstIP not in dstIPData.keys():
            dstIPData[dstIP]=0
        srcMACData[srcMAC]+=length
        srcIPData[srcIP]+=length
        dstMACData[dstMAC]+=length
        dstIPData[dstIP]+=length
            
        csv_write.writerow([current_time,srcMAC,srcIP,dstMAC,dstIP,length])
        if time.time()-start>5:
            start=time.time()
            csv_write.writerow(["累计数据量："])
            csv_write.writerow(["源MAC：",srcMACData])
            csv_write.writerow(["源IP：",srcIPData])
            csv_write.writerow(["目的MAC：",dstMACData])
            csv_write.writerow(["目的IP",dstIPData])
    except:
        pass
    
out.close()










