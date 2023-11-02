#!/usr/bin/python

#!from scapy.all import *
import datetime
import socket
import struct 
import csv
from ctypes import *  
import sys


class IPHeader(Structure):
       
      
      _fields_ = [
         ("ihl",              c_ubyte, 4),
         ("version",          c_ubyte, 4),
         ("tos",              c_ubyte),
         ("len",              c_ushort),
         ("id",               c_ushort),
         ("offset",           c_ushort),
         ("ttl",              c_ubyte),
         ("protocol_num",     c_ubyte),
         ("sum",              c_ushort),
         ("src",              c_uint32),
         ("dst",              c_uint32)
      ]
    
    


      def __new__(self,data=None):
           
          ## lets make a structure of our packets captured 
             return self.from_buffer_copy(data)
      
      def __init__(self,data=None):
            
            self.source_ip = socket.inet_ntoa(struct.pack("@I",self.src))
            self.destination_ip = socket.inet_ntoa(struct.pack("@I",self.dst))
             
            self.protocols = {1:"ICMP",6:"TCP",17:"UDP"}
            try: 
              self.protocol = self.protocols[self.protocol_num]
            except:
              self.protocol = str(self.protocol_num)



def conn():
      
      sock = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_TCP)  
      sock.bind(("0.0.0.0",0))
      sock.setsockopt(socket.IPPROTO_IP,socket.IP_HDRINCL,1)
      return sock 

def options():
    print("========== WELCOME TO PYTHON PACKET SNIFFER ==========\n\n")
    print("Select an option\n")
    
    print("\n1.What is my IP :\n\n")
    
    print("2.Sniff Packets\n\n")
    print("3.--------------\n\n")
    choice = int(input('Option: '))
    if(choice == 1):
       print("!")
       
    elif(choice == 2):
       sniffer = conn()
       
    elif(choice ==3 ):
   # no error handling is done here, excuse me for that
     hostname = sys.argv[1]
   # IP lookup from hostname
     print(f'The {hostname} IP Address is {socket.gethostbyname(hostname)}')
        
      
      
def main():
       
       option = options()
       print ("Sniffer Started: ")
       # Get the raw Packets
       while True:
          try:   
            sniffer = conn()
            raw_pack = sniffer.recvfrom(65535)[0]
            ip_header = IPHeader(raw_pack[0:20])
            if(ip_header.protocol == "TCP"):
                x = datetime.datetime.now()
                string = x.strftime('%Y-%m-%d %H:%M:%S')
                ip= ["Time: "+string+ "\tProtocol: " + ip_header.protocol + "\tSource: " + ip_header.source_ip + "\tDestination: " + ip_header.destination_ip +"\n"]
                ipp = "Time: "+string+ "\tProtocol: " + ip_header.protocol + "\tSource: " + ip_header.source_ip + "\tDestination: " + ip_header.destination_ip +"\n"
                ippp = string+"\t", ip_header.protocol+"\t", ip_header.source_ip+"\t",ip_header.destination_ip
            print (ipp)  
            with open('readttxt', 'a') as f:
                
                f.writelines(ip)
                f.close
            with open('countries.csv', 'a', encoding='UTF8', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(ippp)
                f.close
          except KeyboardInterrupt:
             print ("Exiting....")
             exit(0)
        


main()