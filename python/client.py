#!/bin/python3

from conf import analyse_args, CLIENT_PORT, SERVER_PORT, MAX_PACKET_SIZE
import socket
import select
import getopt
import sys
import os.path


import smfsp

verbose = False

sock = socket.socket(
    socket.AF_INET,
    socket.SOCK_DGRAM | socket.SOCK_NONBLOCK)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
broad_sock = socket.socket(
    socket.AF_INET,
    socket.SOCK_DGRAM | socket.SOCK_NONBLOCK)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)

def receive_from(sock_list, timeout=1.0, bufsz = MAX_PACKET_SIZE):
    s, _, _ = select.select(sock_list, [], [], timeout)
    for sock in s:
        if verbose:
            print(f"Reading data from sock: {sock.getsockname()}")
        bytes, address = sock.recvfrom(bufsz)
        return (bytes, address, sock)
    return (None, None, None)
    #raise Exception("Timeout!")



def main():
    global verbose
    # parse options
    optlist, _ = getopt.gnu_getopt(sys.argv[1:], 'p:i:v')
    # parse arguments
    opts = analyse_args(optlist, isserver=False)
    verbose = opts["verbose"]

    # everithing has been checked, bind socket
    binding = (opts['bind_addr'], opts['bind_port'])
    if verbose:
        print("Try to bind client to: ", binding)
    sock.bind(binding)
    if verbose:
        print("Try to bind broadcast socket")
    broad_sock.bind(('<broadcast>', opts['bind_port']))
    if verbose:
        print("All sockets bound!")

    test_server = ('255.255.255.255', SERVER_PORT)
    smfsp.send_client_hello(sock, test_server)
    print()
    print("Client test loop:")
    while True:
        bytes, address, _ = receive_from([sock, broad_sock], timeout=None)
        print('\treceived packet from:', address)
        msg_type, content = smfsp.parse_packet(bytes)
        print('\tType:', smfsp.type2name(msg_type))
        print('\tData:', content)
        print()
        


if __name__ == "__main__":
    main()

