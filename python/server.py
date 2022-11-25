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

broadcast_client = ('255.255.255.255', CLIENT_PORT)

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
    if verbose:
        print("Broadcast server hello packet")
    smfsp.send_server_hello(sock, clients, fmap)
    # has the server some work to complete?
    pendig_work = False
    # list of requested chunks
    req_chunks = []
    # control structure to avoid sending twice the same chunk
    waiting_chunks = {}
    for file in fmap:
        waiting_chunks[file] = set()
    # send no more than PACKETS_PER_ITERATION packets
    # before checking for ner inputs
    MAX_PACKETS_PER_ITERATION=4
    while True:
        if pendig_work:
            # handle work
            for _ in range(MAX_PACKETS_PER_ITERATION):
                if len(req_chunks) <= 1:
                    # no more works after this
                    pendig_work = False
                    if len(req_chunks) == 0:
                        break
                w = req_chunks.pop(0)
                # remove chunk from control list
                waiting_chunks[w['file']].remove(w['cnk_idx'])
                if verbose:
                    print(f"Sending chunk {w['cnk_idx']} of file {w['file']}")
                smfsp.send_chunk(sock, broadcast_client, fmap, w['file'], w['cnk_idx'])
                # after having sent the last chunk?

        bytes, sender, _ = receive_from(socket_list,
                                # cannot wait if something is waiting!
                                timeout=None if pendig_work else timeout)
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
            elif msg_type == smfsp.CNK_LIST_REQ:
                # check file is owned
                if content['name'] not in fmap:
                    if verbose:
                        print(f"Unknown file {content['name']}")
                    # nothing to do, go on
                    continue
                # get file info
                fmeta = fmap[content['name']]
                # check on file size
                if content['size'] != fmeta['size']:
                    # size mismatch!
                    if verbose:
                        print(f"Mismatch in file [{content['name']}] size: {content['size']} instead of {fmeta['size']}")
                    # nothing to do, go on
                    continue
                # send, one by one, all required chunks
                for cnk_idx in content['cnk_list']:
                    # do not send the same chunk twice
                    if not cnk_idx in waiting_chunks[content['name']]:
                        waiting_chunks[content['name']].add(cnk_idx)
                        w = {
                            'file': content['name'],
                            'cnk_idx': cnk_idx,
                        }
                        req_chunks.append(w)
                        if verbose:
                            print("Register work:", w)
                        pendig_work = True

        # Timeout! Send server hello!
        elif not pendig_work:
            # but only if no work is pending!
            if verbose:
                print("Broadcast server hello packet")
            smfsp.send_server_hello(sock, clients, fmap)


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

    server_loop([sock, broad_sock], fmap)

if __name__ == "__main__":
    main()

