
import ipaddress
import select

# UDP ports used by client and server
SERVER_PORT = 5050
CLIENT_PORT = 5051

CLIENT_BROADCAST = ('255.255.255.255', CLIENT_PORT)

# address to send packet to
IPv4_BRD = '255.255.255.255'

# maximum UDP payload
MAX_PACKET_SIZE = 1400
# maximum amount of file data in a single packet
DEFAULT_CHUNK_SIZE = 1024
# maximum number of chunks requested in a single
# request message sent by clients to a server
MAX_CHUNKS_PER_REQ = 128

def analyse_args(optlist, isserver=False):
    verbose = False
    bind_addr = '127.0.0.1'
    bind_port = SERVER_PORT if isserver else CLIENT_PORT
    for k,v in optlist:
        if k == '-p':
            bind_port = int(v)
        elif k == '-i':
            bind_addr = ipaddress.ip_address(v).__str__()
        elif k == '-v':
            verbose = True
        else:
            raise Exception("Unrecognised option: " + k)
    return {
        'verbose': verbose,
        'bind_addr': bind_addr,
        'bind_port': bind_port,
    }

