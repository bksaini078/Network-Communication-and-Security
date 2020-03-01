#!/usr/bin/env python
# coding: utf-8

# In[ ]:


# Author
# Bhupender Kumar Saini (219 100 887)
# Jan Bings (216 200 708) 
# Ravineesh Goud (219 100 836) 
# Marvin Schwenkmezger (216 201 620) 


# In[7]:


import socket
import json
import ipaddress as ip
from random import randint
import binascii as bi
import hashlib
import sys
import random
import datetime
import uuid
import time 
# #Packet type 
# """Hello 
# Hello_Ack
# Close
# Not_available
# CHAL_PKT
#REQ_AUTH
#AUTH_SUCCESS
#AUTH_FAILED
#DATA_REQUEST
#DATA_RESPONSE"""

#json file format
Packet_Structure  = {
    "Source_Address": "",#source Ip address
    "Destination_Address": "",#desitination IPV4 address
    "S_PortNumber": "",  # this is Sources port number
    "D_PortNumber": "", #this is destination port number 
    "Packet_Type": "",#packet type Hello-1,Hello-Ack-2, Close-3,Non-available-4, Chal_Packet=5
    "Protocol_ID": "",#16byte long unique protocol id to determine the protocol
    "Sequence_Number": "",   #sequence number (0-65535)r
    "Session_ID": "",#16 byte session id
    "Authorization_ID":"",
    "Message": "", #data
    "Timestamp": "",
    "Checksum": "",#for integrity of message

}


#server side
#this function will perform three way handshake and after completion of handshake
# server will send the session key to establish the session
#between server and client.
#this function is basically three way handshake where we have included 
#HELLO - HELLO_ACK-HELLO- HELLO_ACK then generate session ID 
def Handshake(packet,source_Address):
    session_ID=0
# to send session id if 2 hello came 
    packet['Packet_Type']='HELLO_ACK'
    if packet['Sequence_Number']==2:
        packet["Session_ID"]= str(uuid.uuid1())

    return packet

#function to generate unique auth ID, can be increased 
def Generate_AuthID():
    return str(uuid.uuid4())

#this function to generate CRC of the packet 
def CRC_Generate(packet1):
    packet_copy=packet1.copy()
    
    #deleting key to calculate checksum
    del packet_copy['Checksum']
    result  = json.dumps(packet_copy)
    #   print(type(result))
    #https://docs.python.org/2/library/binascii.html for reference .
    crc = bi.crc32(result.encode('utf-8'))
    return crc

#this function will verify for the data integrity 
def CRC_Verify(packet2):
    crc_recv=packet2["Checksum"]
    crc_gen=CRC_Generate(packet2)
#     print(crc_gen)
    return crc_recv==crc_gen

#for sending data packets 
def Send_DataPackets(data_JSON,src_Address,sock):
    try:
        #creating packet
        hostname = socket.gethostname()
        IPAddr = socket.gethostbyname(hostname)
        packet['Source_Address']=IPAddr
        packet['Destination_Address']= source_Address[0]
        packet['D_PortNumber']= source_Address[1]
        packet['S_PortNumber']= sock.getsockname()[1]
        packet['Protocol_ID']= 'Secure_Protocol_Assignment_2'
        d = datetime.datetime.utcnow()
        data_JSON['Timestamp']= str(d.isoformat("T"))
        crc= CRC_Generate(data_JSON)
        data_JSON['Checksum']= crc
        Message_json = json.dumps(data_JSON).encode("utf-8")
        sock.sendto(Message_json, src_Address)
        status= True
    except Exception as e:
        sock.close()
        print("Error while sending data:",e)
        
    return status 

#receiving data packets 
def Receive_DataPackets(sock):
    try:
        data,source_Address=sock.recvfrom(BUFFER_SIZE)
        data = json.loads(data)
#         print("In Receive_DataPackets",data)
        status = True

    except Exception as e:
        sock.close()
        status= False
        print("Error while receiveing data:",e)
        
    return data,source_Address,status


#the CHAP authentication 
#so that when performing handshake we can also authorize the client and provide session ID 
#if client succeed in CHAP authentication otherwise close the connection.
#creating challenges     
def Create_Challenge():
    identifier = randint(0,255)
    return identifier

#verifying challenges 
def Verify_Challenge(packet,identifier):
    secret_Code= "Password"
    hash1 = hashlib.sha256((str(identifier)+secret_Code).encode("utf-8"))
    hash_r= packet['Message']
#     print(hash_r,str(hash1.hexdigest()))
#     print("VerifyChallenge",str(hash1.hexdigest())== hash_r)
    return str(hash1.hexdigest())== hash_r

#creating challage response 
def Create_Chal_Reponse(identifier):
    secret_Code= "Password"
    hash1 = hashlib.sha256((str(identifier)+secret_Code).encode("utf-8"))
    return hash1  

#checking user details are present at server end or not.
def Verify_User(packet,Username_Details):
    return packet['Message'] in Username_Details

#details of the meter reading 
#this function is to send some random data for DATA response 
def Meter_Reading():
    current=random.randrange(0, 10, 1)
    voltage=random.randrange(0, 230, 3)
    meter_Reading={"Current":current, "Voltage":voltage}
    return meter_Reading

#generating public and private keys , using asymmetric encryption 

def Generate_Keys():
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend())
    public_key = private_key.public_key()
    #saving_private key to the file 
    pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption())
    with open('private_key.pem', 'wb') as f:
        f.write(pem)
    #saving public key to file 
    pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo)
    with open('public_key.pem', 'wb') as f:
        f.write(pem)
        
#for encrypting message
def Encrypt_Message(message):
    #reading keys 
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
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

#for decrypting message
def Decrypt_Message(encrypted):
    #reading keys 
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
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
    
    return original_message


# In[8]:



Username_Details=['machine1'] # require for authentication 
protocol_ID = "Secure_Protocol_Assignment_2" #Unique protocol id to determine the protocol

s = socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
s.settimeout(200)


try:
    BUFFER_SIZE = 1024
    #defining port number
    port = 14005
    #binding with the port number
    s.bind(('', port))
    print("Socket successfully created: Port Number-",port)
#     print("socket binded to %s" % (port))
    print("socket is listening\n\n")
    #receiving message from the client
    status=True
    
    while status:
        #receiving packet 
        packet,source_Address,status= Receive_DataPackets(s)
        print("Received(CLIENT):",packet['Packet_Type'])
        print("TimeStamp:",packet['Timestamp'])
#         print(packet)
        #generating CRC for packet integrity 
        crc= CRC_Verify(packet)
        
        print("Verified CRC:",crc)
        if crc and packet['Protocol_ID']==protocol_ID :#if this check is true 
            #checking message if it for handshake 
            if packet['Packet_Type']=='HELLO':
#                 print(packet['Packet_Type'])
                
                #Performing handshaking 
                packet = Handshake(packet,source_Address)
            
            #taking session_ID to verify 
                session_ID=packet['Session_ID']
#               print(packet)
           
                #sending data message 
                print("\n\n\t\t\t\t\t\t\t\tSending(SERVER):",packet['Packet_Type'])
#                print(packet)
                status=Send_DataPackets(packet,source_Address,s)
                
             #replying for authorization request   
            if packet['Session_ID'] == session_ID and packet['Packet_Type']=='REQ_AUTH':
#                 print("in REQ_AUTH IF condition")
                if Verify_User(packet,Username_Details):
                    packet['Message']=Create_Challenge()
                    identifier_V=packet['Message']
                    packet['Packet_Type']='CHAL_PKT'
                    status=Send_DataPackets(packet,source_Address,s)
                    print("\n\t\t\t\t\t\t\t\tSending(SERVER):",packet['Packet_Type'])
                else:
                    packet['Packet_Type']='DISCONNECT'
                    packet['Message']='UserName is wrong'
                    status=Send_DataPackets(packet,source_Address,s)
                    print("\n\t\t\t\t\t\t\t\tSending(SERVER):",packet['Packet_Type'])
                
                
             #for verifying challenge        
            if packet['Session_ID'] == session_ID and packet['Packet_Type']=='RES_CHALL':
#                 print("in RES_CHALL IF condition")
                if Verify_Challenge(packet,identifier_V):
                    packet['Packet_Type']='AUTH_SUCCESS'
                    packet['Message']= 'Authentication Successful'
                    packet['Authorization_ID']= Generate_AuthID()
                    #taking session Authorization ID 
                    Auth_ID =packet['Authorization_ID']
                    status=Send_DataPackets(packet,source_Address,s)
                    print("\n\t\t\t\t\t\t\t\tSending(SERVER):",packet['Packet_Type'])
                else:
                    packet['Packet_Type']='AUTH_FAILED'
                    packet['Message']='Authentication failed, Closing Connection'
                    status=Send_DataPackets(packet,source_Address,s)
                    print("\n\t\t\t\t\t\t\t\tSending(SERVER):",packet['Packet_Type'])
                    
             #to verify the packets is data request        
            if packet['Session_ID'] == session_ID and packet['Packet_Type']=='DATA_REQUEST' and packet['Authorization_ID']==Auth_ID:
                packet['Packet_Type']= 'DATA_RESPONSE'
                print("\n\t\t\t\t\t\t\t\tSending(SERVER):",packet['Packet_Type'])
                msg=Meter_Reading()
                print("\nOriginal Value sent:",msg)
                packet['Message']=Encrypt_Message(str(msg).encode('utf-8'))
                packet['Message']=str(bytes.hex(packet['Message']))
#                 print("*********SENT********")
#                 print(packet)
                print("\nEncrypted value sent:",packet['Message'])
                status=Send_DataPackets(packet,source_Address,s)
            #for closing the connetion 
            if packet['Session_ID'] == session_ID and packet['Packet_Type']=='CLOSE' and packet['Authorization_ID']==Auth_ID:
                print("\n\n\t\t\tClient terminated the connection.....")
                status= False
                s.close()
            
            time.sleep(2)    
        else:
            print("Something wrong, Closing Connection:")
            print(packet)
            status= False
            s.close()
            
            
except socket.timeout as e:
    print("Connection Time out, Closing connection:",e)
    status= False
    s.close()
    print(e)
    


# In[ ]:




