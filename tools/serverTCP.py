#!/usr/bin/env python3 -u

import json
import hashlib
import socket
import sys
import time
import random

HOST = '127.0.0.1'
PORT = 33000

print("Started Server: PORT {}".format(PORT))
try:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen()
    
        conn, addr = s.accept()
    
        with conn:
            print('Connected by {}:{}'.format(addr[0], addr[1]))
            n=-1
            while True:
                # Generate random numbers from 0 to 999
                n =  random.randint(0,999)
                payload = hashlib.md5(bytearray(n)).hexdigest()

                # Create dict{}
                payload = {"id": n, "hash": payload}
            
                # Mount JSON             
                data = json.dumps(payload)
            
                # Print JSON
                print("PAYLOAD: {}".format(data), flush=True)
                sys.stdout.flush()

                # Send JSON via Socket
                conn.sendall(bytes(data, encoding='utf-8'))
            
                # Sleep 5s
                time.sleep(.100)
except KeyboardInterrupt:
    pass

finally:
    print("Bye...")
