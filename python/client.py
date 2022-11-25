#!/bin/python3

from conf import analyse_args, CLIENT_PORT, SERVER_PORT, MAX_PACKET_SIZE
import conf
import socket
import select
import getopt
import sys
import os.path
import random

import smfsp

verbose = False
server_broadcast = ('255.255.255.255', SERVER_PORT)
download_timeout = 0.010    # 10 ms


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

def handle_download(remote_file, download_location, expected_size):
    max_chunk_sz = conf.DEFAULT_CHUNK_SIZE
    # calculate number of chunk to download
    Nchunks = (expected_size + max_chunk_sz-1)//max_chunk_sz

    # set of chunks to be required
    all_chunks = list(range(Nchunks))

    # chunks required in a single iteration
    some_chunks = []
    # create file that will store the content
    with open(download_location, 'wb') as f:
        # repeat until the whole file has beed download
        while len(all_chunks) > 0:
            # in every loop, sent a request to the server
            # listing some chunks and wait for them

            # RANDOM APPROACH - randomly choices a subset
            # of the chunks
            # select chunks to require
            some_chunks += random.sample(all_chunks,
                min(conf.MAX_CHUNKS_PER_REQ, len(all_chunks))-len(some_chunks))
            # sort to be cache friendly
            some_chunks.sort()
            # send request to server
            smfsp.send_chunk_list_req(sock, server_broadcast,
                remote_file,
                expected_size,
                some_chunks)
            if verbose:
                print("Sent request for chunks:", some_chunks)
            
            # wait for server response
            while len(some_chunks) > 0:
                bytes, _, _ = receive_from([sock, broad_sock], timeout=download_timeout)
                # if timeout bread and query again the server
                if bytes == None:
                    if verbose:
                        print("Timeout! Missing:   ", some_chunks)
                        print("Timeout! all_chunks:", all_chunks)
                    break   # if it timeouts, it resend a chunk request
                msg_type, content = smfsp.parse_packet(bytes)
                if verbose:
                    print(f"Received {smfsp.type2name(msg_type)} packet: {content}")
                if msg_type != smfsp.CNK_OFFER:
                    # receive unwanted packet
                    pass
                    # do nothing - may cause starvation - should be
                    # fixed
                else:
                    if verbose:
                        print("Received CHUNK!")
                    # check correct chunk
                    # salva il chunk
                    description = {
                        'name': content['name'],
                        'size': content['size'],
                        'cnk_offset': content['cnk_offset'],
                        'cnk_size': content['cnk_size'],
                        'last_cnk': content['last_cnk'],
                    }
                    print(f"Received chunk for {description}")
                    # check if it was expected
                    if content['name'] == remote_file and content['size'] == expected_size:
                        # chunk of the requested packet
                        # were we waiting for it?
                        cnk_idx = content['cnk_offset'] // max_chunk_sz
                        if cnk_idx in all_chunks:
                            # assert valid chunk size
                            if content['last_cnk'] and content['cnk_offset']+content['cnk_size'] != expected_size:
                                raise Exception(f"Invalid last chunk: offset: {content['cnk_offset']} cnk_size: {content['cnk_size']} file_size: {expected_size}")
                            elif not content['last_cnk'] and content['cnk_size'] != conf.DEFAULT_CHUNK_SIZE:
                                raise Exception(f"Invalid chunk size: {content['cnk_size']} instead of {conf.DEFAULT_CHUNK_SIZE}")

                            # chunk is then valid, so write it
                            f.seek(content['cnk_offset'])
                            f.write(content['data'])

                            # remove chunk from expected
                            all_chunks.remove(cnk_idx)
                            if cnk_idx in some_chunks:
                                some_chunks.remove(cnk_idx)
                        else:
                            if verbose:
                                print(f"Chunk {cnk_idx} already received, missing:")
                                print("\tsome_chunks: ", some_chunks)
                                print("\tall_chunks:  ", all_chunks)
    if verbose:
        print("File fully received!")


# handle interaction with user to download requested file
# fileitem: dict{'size', 'name', 'server'}
def download_file(fileItem):
    remote_file = fileItem['name']
    remote_srvr = fileItem['server']
    expected_size = fileItem['size']
    download_location = os.path.abspath(remote_file)
    print(f"Download file {remote_file} from server {remote_srvr}")
    ok = False
    while not ok:
        name_ok= False
        while not name_ok:
            print(f"The downloaded file will be stored at: '{download_location}', is it ok?")
            print("\t[none to confirm, otherwise give new path]=> ", end='')
            candidate = input().strip()
            if candidate.strip() == '':
                name_ok = True
            else:
                download_location = os.path.abspath(candidate)
        if os.path.exists(download_location):
            print(f"File '{download_location}' already exists, are you SURE to overwrite it? [y/N] ", end='')
            candidate = input().strip().lower()
            if candidate == 'y':
                print("The file will be overwritten!")
                ok = True
            else:
                print("Please, choose a new location for the download")
        else:
            ok = True
    print(f"Downloadind file {remote_file} to {download_location}...")

    # start the download
    handle_download(remote_file, download_location, expected_size)


def main():
    global verbose
    global server_broadcast

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

    smfsp.send_client_hello(sock, server_broadcast)
    print()
    if verbose:
        print("Client test loop:")
    hello_received = False
    available_files = {}
    print("Send ^C to stop or chose file to download")
    print("C")
    try:
        while True:
            bytes, address, _ = receive_from([sock, broad_sock], timeout=None)
            print('\treceived packet from:', address)
            msg_type, content = smfsp.parse_packet(bytes)
            print('\tType:', smfsp.type2name(msg_type))
            print('\tData:', content)
            print()
            if msg_type == smfsp.SRV_HELLO:
                for k,v in content.items():
                    if not k in available_files:
                        available_files[k] = {
                            'name': k,
                            'size': v,
                            'server': address,
                        }
                hello_received = True
                print("Interrupt to choose file to download")
    except KeyboardInterrupt:
        if hello_received:
            decided = False
            # copy to list to simplify selection
            l = list(available_files.values())
            while not decided:
                print("Files available for download:")
                for i,f in zip(range(len(l)), l):
                    print(f"{i})\tfile:{f['name']}\tsize: {f['size']}\tserver: {f['server']}")
                print(f"Which file to download? [{0} - {len(l)-1}] ", end='')
                try:
                    val = input()
                    index = int(val)
                except ValueError:
                    print("Invalid input:", val)
                    continue
                if 0 <= index < len(l):
                    print(f"Are yout sure to download file {index}: {l[index]}? [y/N] ", end='')
                    val = input()
                    if val.lower() == 'y':
                        print("Start download")
                        decided = True
                    else:
                        print("Discarded, repeat")
            
            download_file(l[index])
                    
        else:
            print("Interrupted without having received any file to download, exit")
            exit(0)
    


if __name__ == "__main__":
    main()

