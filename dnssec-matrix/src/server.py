import socketserver
import struct
import hashlib
import sys
import os

def compute_next(node, salt, iters):
    curr = (node + salt).encode()
    for _ in range(iters):
        curr = hashlib.sha1(curr).digest()
    return curr.hex()

nodes = ["start"]
salts = ["init_salt_42", "node_alpha_x", "crypto_bridge_99", "almost_there_sec", "final_hop_1337"]
iters_list = [100, 250, 500, 750, 1000]

# Precompute the sequential valid nodes
for i in range(5):
    nodes.append(compute_next(nodes[-1], salts[i], iters_list[i]))

class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request[0]
        sock = self.request[1]
        try:
            resp = self.build_dns_response(data)
            if resp:
                sock.sendto(resp, self.client_address)
        except Exception as e:
            # Silently ignore bad packets
            pass

    def build_dns_response(self, query_data):
        if len(query_data) < 12:
            return b''
            
        header = struct.unpack('>HHHHHH', query_data[:12])
        id, flags, qdcount, ancount, nscount, arcount = header
        
        # We only support single question queries
        if qdcount != 1:
            return b''
            
        offset = 12
        qname_parts = []
        try:
            while True:
                length = query_data[offset]
                if length == 0:
                    offset += 1
                    break
                if length >= 192:
                    offset += 2 # basic compression pointer check
                    break
                qname_parts.append(query_data[offset+1:offset+1+length].decode('utf-8').lower())
                offset += length + 1
        except Exception:
            return b''
            
        try:
            qtype, qclass = struct.unpack('>HH', query_data[offset:offset+4])
        except Exception:
            return b''
            
        # QR=1, AA=1
        resp_flags = 0x8400
        question = query_data[12:offset+4]
        qname = ".".join(qname_parts)
        
        answers = b''
        authorities = b''
        resp_ancount = 0
        resp_nscount = 0
        
        def build_txt(text):
            # Encode TXT string chunks if length > 255 (though our strings are short)
            # Standard single chunk
            rdata = bytes([len(text)]) + text.encode()
            return struct.pack('>HHHIH', 0xc00c, 16, 1, 300, len(rdata)) + rdata
            
        def build_nsec3(iters, salt_str):
            salt_bytes = salt_str.encode()
            next_hash = hashlib.sha1(b'dummy_boundary').digest()
            rdata = struct.pack('>BBHB', 1, 0, iters, len(salt_bytes))
            rdata += salt_bytes
            rdata += struct.pack('>B', len(next_hash))
            rdata += next_hash
            rdata += b'\x00\x01\x40' # Type Bit Maps for A
            return struct.pack('>HHHIH', 0xc00c, 50, 1, 300, len(rdata)) + rdata

        # Custom Routing logic for the matrix.ctf challenge
        is_matrix = len(qname_parts) >= 2 and qname_parts[-2] == "matrix" and qname_parts[-1] == "ctf"
        
        if is_matrix:
            if qname == "start.matrix.ctf" and (qtype == 16 or qtype == 255):
                answers = build_txt("Welcome. Query a nonexistent name at *.wild.start.matrix.ctf to find the path.")
                resp_ancount = 1
            elif qname == f"{nodes[5]}.matrix.ctf" and (qtype == 16 or qtype == 255):
                answers = build_txt(os.getenv("FLAG", "flag{dn553c_n53c3_w1ldc4rd_w4lk3r}"))
                resp_ancount = 1
            elif len(qname_parts) >= 5 and qname_parts[-4] == "wild":
                node = qname_parts[-3]
                if node in nodes[:-1]:
                    idx = nodes.index(node)
                    resp_flags |= 3 # NXDOMAIN
                    authorities = build_nsec3(iters_list[idx], salts[idx])
                    resp_nscount = 1
                else:
                    resp_flags |= 3 # NXDOMAIN
            else:
                resp_flags |= 3 # NXDOMAIN
        else:
            resp_flags |= 3 # NXDOMAIN
            
        if resp_ancount == 0 and resp_nscount == 0 and (resp_flags & 0x000F) == 0:
            resp_flags |= 3 # NXDOMAIN
            
        resp_header = struct.pack('>HHHHHH', id, resp_flags, 1, resp_ancount, resp_nscount, 0)
        return resp_header + question + answers + authorities

if __name__ == "__main__":
    HOST, PORT = "0.0.0.0", 53
    print(f"Starting DNSSEC CTF Server on {HOST}:{PORT}")
    server = socketserver.UDPServer((HOST, PORT), DNSHandler)
    server.serve_forever()
