
import hashlib
import os

import conf

# int to bytes
def i2b(n, limit=4):
    return n.to_bytes(limit, 'big')
def b2i(b):
    return int.from_bytes(b, 'big')

# serialize short string (up to 255 characters)
def serialize_short_str(s):
    b = s.encode('utf-8')
    l = len(b)
    if not 0 < l < 256:
        raise Exception("String length outside validity range (0,256)")
    return i2b(l, limit=1)+b


def serialize_short_string_sequence(strings):
    l = len(strings)
    if not 0 < l < 256:
        raise Exception("String sequence length outside validity range (0,256)")
    buf = i2b(l, limit=1)
    for s in strings:
        buf += serialize_short_str(s)
    return buf

def serialize_fname_sz_seq(fmap):
    l = len(fmap)
    if not 0 < l < 256:
        raise Exception("String length", l, "outside validity range (0,256)")
    buf = i2b(l, limit=1)
    for name,info in fmap.items():
        buf += serialize_short_str(name) + i2b(info['size'], limit=8)
    return buf


# Extract payload content from SERVER_HELLO
# offset: used to avoid generating new byte buffers
#   on every function call
# return tuple
#   (data, final_offset)
def __extract_file_data(b, offset=0):
    # get items count
    if len(b) - offset < 1:
        raise Exception("Malformed buffer - missing length")
    scount = b2i(b[offset:offset+1])
    offset += 1
    ans = {}
    # for all listed files
    for _ in range(scount):
        # ensure all data available
        if len(b) - offset < 1:
            raise Exception("Malformed buffer")
        strlen = b2i(b[offset:offset+1])
        offset += 1
        # ensure there is enough space for file name and length
        if len(b) - offset < strlen + 8:
            raise Exception("Malformed buffer")
        ans[b[offset:offset+strlen].decode()] = b2i(b[offset+strlen:offset+strlen+8])
        offset += strlen + 8
    return (ans, offset)

# used to parse body of CNK_OFFER
def __extract_chunk(b, offset=0):
    buflen = len(b)
    # expected structure:
    #   name of the file  [short string]
    #   total file size   [long]
    #   chunk offset      [long]
    #   chunk size        [long]
    #   last chunk        [byte]
    # name is variable length, other part
    # has fixed size of 25 bytes
    HEADERLEN = 25

    # EXTRACT FILENAME
    if buflen - offset < 1:
        raise Exception("Malformed buffer - missing filename length")
    strlen = b2i(b[offset:offset+1])
    offset += 1
    # ensure there is enough space for file name and length
    if buflen - offset < strlen:
        raise Exception("Malformed buffer - missing filename")
    filename = b[offset:offset+strlen].decode()
    offset += strlen

    # are all 25 bytes present?
    if buflen - offset < HEADERLEN:
        raise Exception("Malformed buffer - missing header")

    # get total file size    
    size = b2i(b[offset:offset+8])
    offset += 8
    # get chunk offset
    cnk_offset = b2i(b[offset:offset+8])
    offset += 8
    # get chunk size
    cnk_size = b2i(b[offset:offset+8])
    offset += 8
    # last chunk?
    last_cnk = b2i(b[offset:offset+1]) != 0
    offset += 1

    # check payload presence?
    if buflen - offset < cnk_size:
        raise Exception("Malformed buffer - missing chunk content")
    data = b[offset:offset+cnk_size]
    offset += cnk_size

    return ({
        'name': filename,
        'size': size,
        'cnk_offset': cnk_offset,
        'cnk_size': cnk_size,
        'last_cnk': last_cnk,
        'data': data
    }, offset)

# check packet checksum
#   buffer  =>  packet content in byte
def __assert_packet_checksum(buffer, offset):
    payloadlen = offset
    buflen = len(buffer)
    # assert presence of hash type
    if buflen < offset + HASH_LENGTH:
        raise Exception("Malformed packet: no space for hash type")
    hash_type = buffer[offset:offset+HASH_LENGTH]
    offset += HASH_LENGTH
    # check header type
    if hash_type == HASH_NONE:
        pass # ok, nothing to do
    elif hash_type == HASH_SHA256:
        h = hashlib.sha256(buffer[:payloadlen]).digest()
        lh = len(h)
        # hash present?
        if buflen != offset + lh:
            raise Exception("Malformed packet: no space for hash content")
        # hash value
        if h != buffer[offset:offset+lh]:
            raise Exception("Malformed packet: hash check failed")
        # ok
        pass
    else:
        raise Exception("Unknown hash type")


# Packet structure:
# HEADER
MAGIC_LENGTH = 8
#   8 byte magic
MAGIC = b'SMFSP001'[:MAGIC_LENGTH]
#   4 byte message type
TYPE_LENGTH = 4
# packet sent by server listing avilable files
SRV_HELLO = b'SHLO'[:TYPE_LENGTH] # sent by a server
# packet sent by server continaing a chunk of a file
CNK_OFFER = b'OFER'[:TYPE_LENGTH] # sent by a server

# packet sent by client to query for an available server
# packet as no data associated with it, it just ask
# available servers to send thei hello packets
CLN_HELLO = b'CHLO'[:TYPE_LENGTH] # sent by a client

def type2name(pckt_type):
    if pckt_type == SRV_HELLO:
        return "SRV_HELLO"
    if pckt_type == CLN_HELLO:
        return "CLN_HELLO"
    if pckt_type == CNK_OFFER:
        return "CNK_OFFER"
    else:
        raise Exception("Unknown packet type")

# PAYLOAD
#   8 byte length - +4GB allowed
#   data...

# TRAILING
HASH_LENGTH = 4
# 4 byte hash type
HASH_NONE   = i2b(0,    limit=HASH_LENGTH)
HASH_SHA256 = i2b(256,  limit=HASH_LENGTH)

# Optional: if hash tyne != HASH_NONE
#   hash of the previous message calculated
#   accordingly to the specified hash type

# hash and send packet
def __hash_and_send(s, dest_address, msg, hash_type=HASH_SHA256):
    if hash_type == HASH_NONE:
        buff = msg+HASH_NONE
    elif hash_type == HASH_SHA256:
        buff = msg+HASH_SHA256+hashlib.sha256(msg).digest()
    else:
        raise Exception()
    s.sendto(buff, dest_address)

# Send a CNK_OFFER packet
#
# s:        socket used to send the chunk
# destaddr: to who should the packet be sent?
# fmap:     fmap object
# reqfile:  from which file has to be sent  [short string]
# cnk_num:  which chunk should be sent?     [long]
# cnk_sz:   chunk size                      [long]
#
# Files are sent in chunks aligned to chunk size
#   chunk offset => cnk_num*cnk_sz   
def send_chunk(s, dest_addr, fmap, reqfile, cnk_num, cnk_sz=conf.DEFAULT_CHUNK_SIZE, hash_type=HASH_SHA256):
    # offset of the chunk to be sent
    cnk_offset = cnk_num*cnk_sz
    # metadata associated to the file
    fmeta = fmap[reqfile]
    # path of the file to be sent
    filename = fmeta['path']
    # check on file size (to detect changes)
    size = os.path.getsize(filename)
    if size != fmeta['size']:
        # update last size
        fmeta['size'] = size
    #last chunk?
    last_cnk = True if size <= cnk_offset+cnk_sz else False
    # if last chunk returned size must be adjusted
    if last_cnk:
        cnk_sz = size - cnk_offset

    # then packet can be built
    # MAGIC
    # CNK_OFFER <- packet type
    # name of the file  [short string]
    # total file size   [long]
    # chunk offset      [long]
    # chunk size        [long]
    # last chunk        [byte]
    packet = MAGIC + CNK_OFFER + \
        serialize_short_str(reqfile) +\
        i2b(size, limit=8) +\
        i2b(cnk_offset, limit=8) +\
        i2b(cnk_sz, limit=8) +\
        i2b(1 if cnk_sz else 0, limit=1) 

    with open(filename, 'rb') as f:
        f.seek(cnk_offset)
        # add bytes to packet
        packet += f.read(cnk_sz)

    # had trailing hash and send
    __hash_and_send(s, dest_addr, packet, hash_type)


# Build and send a server hello message
def send_server_hello(s, dest_address, fmaps, hash_type=HASH_SHA256):
    packet = MAGIC + SRV_HELLO + serialize_fname_sz_seq(fmaps)
    __hash_and_send(s, dest_address, packet, hash_type)

# Build and send a client hello message
def send_client_hello(s, dest_address, hash_type=HASH_SHA256):
    packet = MAGIC + CLN_HELLO
    __hash_and_send(s, dest_address, packet, hash_type)



# return a tuple
# (header, parsed packet)
# throws if packet HASH
# do not match content
def parse_packet(packet):
    if len(packet) < 8:
        raise Exception("buffer too short")
    offset = 0
    # check magic
    if packet[:MAGIC_LENGTH] != MAGIC:
        raise Exception("Magic mismatch")
    offset += MAGIC_LENGTH
    # type
    msg_type = packet[offset:offset+TYPE_LENGTH]
    offset += TYPE_LENGTH
    # extract payload
    if msg_type == SRV_HELLO:
        content, offset = __extract_file_data(packet, offset)
    elif msg_type == CLN_HELLO:
        content = None # no data associated with a client hello
    elif msg_type == CNK_OFFER:
        content, offset = __extract_chunk(packet, offset)
    else:
        raise Exception("Unknown packet type: " + repr(msg_type))
    # check hash type
    __assert_packet_checksum(packet, offset)

    return (msg_type, content)


