#!/usr/bin/env python
# coding: utf-8

import time
import datetime
import random
import socket
import json
import binascii as bi
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


#Function to solve the challenge response given by the Server
def Create_Chal_Reponse(identifier):
    secret_Code= "Password"
    hash_value = hashlib.sha256((str(identifier)+secret_Code).encode("utf-8"))
    hash_value = hash_value.hexdigest()
    return hash_value

#Function to verify the CRC Value of packet, This is done by comparining by recalculating the CRC of receieved packet
def crc_Verify(packet):
    crc_recv=packet["Checksum"]
    crc_gen=crcSumGenerator(packet)
    return crc_recv==crc_gen


#Function to calculate the CRC Value of packet, 
#This function will generate CRC value of all the fields inside the packet, excluding CRC field
def crcSumGenerator(packet_structure):
    
    #creating a copy of packet
    packet = packet_structure.copy()

    #deleting the field of CRC in packet
    del packet['Checksum']
    #converting the packet in json
    string  = json.dumps(packet)
    #calculating the CRC32 value
    crc_value = bi.crc32(string.encode('utf-8'))

    return crc_value 

#Function for sending packet to Server
def send_packet(packet,sock):
    data_out = json.dumps(packet).encode('utf-8')
    status = sock.sendall(data_out)
    return status


#Function for receiving packet from Server
def receive_packet(sock):

    data,server = sock.recvfrom(4096)
    data_received = json.loads(data)
    print(data_received)

    return data_received


#Function for encrypting the data
def Encrypt_Message(message):
    #reading keys 
    with open("public_key.pem", "rb") as key_file:
        public_key = serialization.load_pem_public_key(
        key_file.read(),
        backend=default_backend())
        #encrypting message
    encrypted = public_key.encrypt(
    message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None))
    
    return encrypted

#Function for decrypting the data
def Decrypt_Message(encrypted):
    #reading keys 
    with open("private_key.pem", "rb") as key_file:
        private_key = serialization.load_pem_private_key(
        key_file.read(),password=None,
        backend=default_backend())
        #encrypting message
        encrypted=bytes.fromhex(encrypted)
    original_message = private_key.decrypt(
    encrypted,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None))
  
    return original_message.decode('utf-8')



#Function for threeway handshake with Server
def threeWayHandShake(server_address):
    
    #Intializing the sequence number
    seq_num = 1
    
    #Creating a UDP Socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
   
    #Connecting with the server
    sock.connect(server_address)
    
    #to fetch the IP address and port number of client
    ip_port = sock.getsockname()
    
    #Intializing the packet with client ip and port details and server ip and port details
    packet['Source_Address']=ip_port[0]
    packet['S_PortNumber']=ip_port[1]
    packet['Destination_Address']='192.168.179.54'
    packet['D_PortNumber']='14005'
    
    #Intializing the packet with Protocol ID
    packet['Protocol_ID']="Secure_Protocol_Assignment_2"

    #Initializing the packet with Sequence number
    packet['Sequence_Number']=seq_num
    
    #Initializing the packet with the type of packet
    packet['Packet_Type'] = request_type[0] #(request_type = "HELLO")
    
    #Calculating the Timestamp and intializing the packet with Timestamp field
    d = datetime.datetime.utcnow()
    packet['Timestamp'] =str(d.isoformat("T")) 

    #Calculating the CRC Value for packet and intializing the packet with CRC Value
    packet['Checksum'] = crcSumGenerator(packet)

    #Sending the data in JSON format to Server
    status = send_packet(packet,sock)   

    #Receiving data from Server
    data_received = receive_packet(sock)
    
    
    #Checking the sequence number and verifying the CRC of packet received !!!
    if((seq_num == data_received['Sequence_Number']) & (crc_Verify(data_received)==True)):
 
        #If the the above condition is true then again sending the packet to Server by intializing all the required 
        #parameter for 3-Way Handshake
        packet['Packet_Type']=request_type[0] #(request_type = "HELLO")
        packet['Sequence_Number']=seq_num+1 #incrementing the sequence number
        
        #Calculating the Timestamp and intializing the packet with Timestamp field
        d = datetime.datetime.utcnow()
        packet['Timestamp'] =str(d.isoformat("T")) 
        
        #Calculating the CRC Value for packet and intializing the packet with CRC Value
        packet['Checksum'] = crcSumGenerator(packet)

        #Sending the data in JSON format to server
        status = send_packet(packet,sock)
        
        #Receiving data from Server
        data_received = receive_packet(sock)

        #Verifying the CRC of received packet
        if(crc_Verify(data_received)==True):
            print('')
    else:
        print("CRC Value not verified ...Closing the Connection!!!!")
        sock.close()
    
    
    return sock,data_received


#Function for authentication with Server
def request_authentication(sock,packet):
    
    #Initializing the packet with the type of packet
    packet['Packet_Type']=request_type[5] #(request_type = "REQ_AUTH")
    
    #Initializing the packet with Sequence number
    packet['Sequence_Number']=packet['Sequence_Number']+1
    
    #Sending the username of device/client which is trying to verify it's identity with Server
    packet['Message']='machine1'
    
    #Calculating the Timestamp and intializing the packet with Timestamp field
    d = datetime.datetime.utcnow()
    packet['Timestamp'] =str(d.isoformat("T")) 

    #Calculating the CRC Value for packet and intializing the packet with CRC Value
    packet['Checksum'] = crcSumGenerator(packet)

    #Sending the data in JSON format to Server
    send_packet(packet,sock)

    #Receiving data from Server
    data_received = receive_packet(sock)
    
    #Calculating the hash value for the Chanllenge response given by the server
    hash_value = Create_Chal_Reponse(data_received['Message'])

    #Verifying the CRC of received packet
    if(crc_Verify(data_received)==True):
    #If the above condition is true then Client will send the challenge response to the Server
        
        #Initializing the packet with the type of packet
        packet['Packet_Type']=request_type[6] #(request_type = "RES_CHALL")
        
        #Initializing the packet with Sequence number
        packet['Sequence_Number']=packet['Sequence_Number']+1
        
        #Initializing the packet with hash value i.e. Response of Challenge provided by the Server
        packet['Message'] = hash_value
        
        #Calculating the Timestamp and intializing the packet with Timestamp field
        d = datetime.datetime.utcnow()
        packet['Timestamp'] =str(d.isoformat("T")) 

        #Calculating the CRC Value for packet and intializing the packet with CRC Value
        packet['Checksum'] = crcSumGenerator(packet)

        #Sending the data in JSON format to Server
        send_packet(packet,sock)
        
        #Receiving data from Server
        data_received = receive_packet(sock)

        #Verifying the CRC of received packet
        if(crc_Verify(data_received)==True):
            print('')
    else:
        print("CRC Value not verified ...Closing the Connection!!!!")
        sock.close()    

    return sock,data_received


#Function to send the data request to server
def request_data(sock,packet):
    
    packet['Message']=''
    
    #Initializing the packet with the type of packet
    packet['Packet_Type']=request_type[3] #(request_type = "DATA_REQUEST")
    
    #Initializing the packet with Sequence number
    packet['Sequence_Number']=packet['Sequence_Number'] + 1
    
    #Calculating the Timestamp and intializing the packet with Timestamp field
    d = datetime.datetime.utcnow()
    packet['Timestamp'] =str(d.isoformat("T")) 

    #Calculating the CRC Value for packet and intializing the packet with CRC Value
    packet['Checksum'] = crcSumGenerator(packet)

    #Sending the data in JSON format to Server
    send_packet(packet,sock)

    #Receiving data from Server
    data_received = receive_packet(sock)

    #Verifying the CRC of received packet
    if(crc_Verify(data_received)==True):
        print('')
    else:
        print("CRC Value not verified ...Closing the Connection!!!!")
        sock.close()
        
    #Checking if the packet received from Server is of type "DATA_RESPONSE" then decrypt the message field of the packet
    #and store the decrypted value in a list 
    if(data_received['Packet_Type']=='DATA_RESPONSE'):
        original_value.append(Decrypt_Message(data_received['Message']))
        

    return sock,data_received

# #server address:-
# server_address = ('141.26.183.207', 14005)
server_address = ('192.168.179.54', 14005)

#message types
request_type=['HELLO','CLOSE','HELLO_ACK','DATA_REQUEST','DATA_RESPONSE','REQ_AUTH','RES_CHALL']

#list to store the decrypted values provided by the Server
original_value=[]

#Structure of packet
packet  = {
    "Source_Address": '', # IP Address of Client
    "Destination_Address": '', # IP Address of Server
    "S_PortNumber": '',  # Port Number of Client
    "D_PortNumber": '', # Port Number of Server
    "Packet_Type": '',# 'HELLO','CLOSE','HELLO_ACK','DATA_REQUEST','DATA_RESPONSE','REQ_AUTH','RES_CHALL'
    "Protocol_ID": '', #16byte long unique protocol id to determine the protocol
    "Sequence_Number": '',   #sequence number (0-65535)
    "Session_ID": '', #16 byte session id
    "Authorization_ID":"", #Provided by the Server to the client once the client is authorized by the Server   
    "Message": '', #data
    "Timestamp":'', #Timestamp filed
    "Checksum": '',#for integrity of message

}


#For three way handshake with Server, This is the starting point of Client's program
sock_handle,data = threeWayHandShake(server_address)

#Intiating the Request authentication with Server
sock_handle,data = request_authentication(sock_handle,data)

#to keep track of time 
t=0

#Using For loop to send data request and receive data response, for demonstration purpose Client is sending
# only 5 Data Request to Server
for i in range(0,5):
    #Sending the Data Request to Server
    print("Sending Data Request :- ",i+1)
    
    sock_handle,data = request_data(sock_handle,data)
    
    #Client starts to send a DATA_REQUEST every 30 seconds, but for demonstration purpose
    #we have set the delay of 2 seconds, it can be changed to time.sleep(30) to match the requirement as mentioned
    #in the requirement document under Application Requirements "Client starts to send a DATA_REQUEST every 30 seconds"
    time.sleep(2)    
    t=t+5
    
    #Closing the connection after 30 minutes
    if(t==20):
        #Initializing the packet with the type of packet
        data['Packet_Type']=request_type[1] #(request_type = "CLOSE")
        
        #Initializing the packet with "Closing the connection" message with Server
        data['Message']='Closing the Connection'
        
        #Initializing the packet with Sequence number
        data['Sequence_Number']=data['Sequence_Number'] + 1
        
        #Calculating the Timestamp and intializing the packet with Timestamp field
        d = datetime.datetime.utcnow()
        data['Timestamp'] =str(d.isoformat("T")) 
        
        #Calculating the CRC Value for packet and intializing the packet with CRC Value
        data['Checksum'] = crcSumGenerator(data)
        
        #Sending the data in JSON format to Server
        send_packet(data,sock_handle)
        
        #Closing the connection with Server
        sock_handle.close()   
        
        print("Closing the Connection")
        break

#Printing the Decrypted Values        
print(original_value)


# In[ ]:




