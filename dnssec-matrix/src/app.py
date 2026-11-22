from flask import Flask, request, jsonify, render_template
import hashlib
import os

app = Flask(__name__)

def compute_next(node, salt, iters):
    curr = (node + salt).encode()
    for _ in range(iters):
        curr = hashlib.sha1(curr).digest()
    return curr.hex()

nodes = ["start"]
salts = ["init_salt_42", "node_alpha_x", "crypto_bridge_99", "almost_there_sec", "final_hop_1337"]
iters_list = [100, 250, 500, 750, 1000]

for i in range(5):
    nodes.append(compute_next(nodes[-1], salts[i], iters_list[i]))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/query', methods=['POST'])
def query():
    data = request.json
    if not data or 'domain' not in data:
        return jsonify({"status": "error", "message": "Missing domain"}), 400
        
    domain = data['domain'].lower().strip()
    qtype = data.get('qtype', 'A').upper()
    
    parts = domain.split('.')
    is_matrix = len(parts) >= 2 and parts[-2] == "matrix" and parts[-1] == "ctf"
    
    if not is_matrix:
        return jsonify({
            "status": "NXDOMAIN",
            "question": f";{domain}. IN {qtype}",
            "answer": [],
            "authority": []
        })

    if domain == "start.matrix.ctf" and qtype in ["TXT", "ANY"]:
        return jsonify({
            "status": "NOERROR",
            "question": f";{domain}. IN {qtype}",
            "answer": [
                f"{domain}. 300 IN TXT \"Welcome. Query a nonexistent name at *.wild.start.matrix.ctf to find the path.\""
            ],
            "authority": []
        })
        
    if domain == f"{nodes[5]}.matrix.ctf" and qtype in ["TXT", "ANY"]:
        # Read flag from /flag.txt (must exist)
        with open('/flag.txt', 'r') as f:
            flag = f.read().strip()
        return jsonify({
            "status": "NOERROR",
            "question": f";{domain}. IN {qtype}",
            "answer": [
                f"{domain}. 300 IN TXT \"{flag}\""
            ],
            "authority": []
        })

    if len(parts) >= 5 and parts[-4] == "wild":
        node = parts[-3]
        if node in nodes[:-1]:
            idx = nodes.index(node)
            return jsonify({
                "status": "NXDOMAIN",
                "question": f";{domain}. IN {qtype}",
                "answer": [],
                "authority": [
                    {
                        "record": f"wild.{node}.matrix.ctf. 300 IN NSEC3 1 0 {iters_list[idx]} -",
                        "diagnostic_hint_salt": salts[idx],
                        "iterations": iters_list[idx],
                        "hash_algo": "SHA-1"
                    }
                ]
            })
            
    return jsonify({
        "status": "NXDOMAIN",
        "question": f";{domain}. IN {qtype}",
        "answer": [],
        "authority": []
    })

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080)
