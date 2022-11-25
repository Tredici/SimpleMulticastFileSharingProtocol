#!/bin/python3

from conf import analyse_args, CLIENT_BROADCAST, CLIENT_PORT, MAX_PACKET_SIZE
import socket
import select
import sys
import os.path
import ipaddress

import getopt


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


def getFileMap(argv):
    ans = {}
    for f in argv:
        if ':' in f:
            k,v = f.split(':')
            if k in ans:
                raise Exception("Duplicated key: " + k)
            ans[k] = os.path.abspath(v)
        elif not f.startswith("-"):
            ans[os.path.basename(f)] = os.path.abspath(f)
    return ans

def check_file_existence(fmaps):
    ans = {}
    for name,path in fmaps.items():
        if not os.path.exists(path):
            raise Exception("File '" + path + "' not found")
        tmp = {
            'name': name,
            'path': path,
            'size': os.path.getsize(path)
        }
        ans[name] = tmp
    return ans

def print_file_map(fmaps):
    for k,v in fmaps.items():
        print('\t', k, '=>', v)

def receive_from(sock_list, timeout=1.0, bufsz = MAX_PACKET_SIZE):
    s, _, _ = select.select(sock_list, [], [], timeout)
    for sock in s:
        if verbose:
            print(f"Reading data from sock: {sock.getsockname()}")
        bytes, address = sock.recvfrom(bufsz)
        return (bytes, address, sock)
    return (None, None, None)
    #raise Exception("Timeout!")


# the server periodically send server hello or, if
# a client hello is received, sent a server hello
# immediately
def server_loop(socket_list, fmap, timeout=1.0, broadcast_addr = '255.255.255.255', client_port=CLIENT_PORT):
    clients = (broadcast_addr, client_port)
    smfsp.send_server_hello(sock, clients, fmap)
    while True:
        bytes, sender, _ = receive_from(socket_list, timeout=timeout)
        if bytes != None:
            # parse message
            msg_type, content = smfsp.parse_packet(bytes)
            print('\tType:', smfsp.type2name(msg_type))
            print('\tData:', content)
            print()
            if msg_type == smfsp.CLN_HELLO:
                if verbose:
                    print("Send server_hello in response to client hello")
                smfsp.send_server_hello(sock, sender, fmap)



def main():
    global verbose
    # parse options
    optlist, args = getopt.gnu_getopt(sys.argv[1:], 'p:i:v')
    # parse arguments
    opts = analyse_args(optlist, isserver=True)
    verbose = opts["verbose"]

    # map of file paths
    pmap = getFileMap(args)
    # check existence of files
    if len(pmap) == 0:
        raise Exception("No file registered, at least one is necessary")
    if verbose:
        print_file_map(pmap)
    fmap = check_file_existence(pmap)

    # everithing has been checked, bind socket
    binding = (opts['bind_addr'], opts['bind_port'])
    if verbose:
        print("Try to bind server to: ", binding)
    sock.bind(binding)
    if verbose:
        print("Try to bind broadcast socket")
    broad_sock.bind(('<broadcast>', opts['bind_port']))
    if verbose:
        print("All sockets bound!")

    test_client = ('255.255.255.255', CLIENT_PORT)
    # main loop - send hello packets
    smfsp.send_server_hello(sock, test_client, fmap)

    # test - send chunk of the first file
    smfsp.send_chunk(sock, test_client, fmap, list(fmap.keys())[0], 0)

    server_loop([sock, broad_sock], fmap)

if __name__ == "__main__":
    main()

