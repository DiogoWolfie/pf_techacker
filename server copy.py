from flask import Flask, jsonify, render_template
import os
import re

app = Flask(__name__)
log_file = "access.log"

def parse_log_line(line):
    log_pattern = r'(.+?) - (.+?):(\d+) -> (.+?):(\d+) - - \[(.+?)\] "(.*?) (.*?) HTTP/1.1" (\d+) (\d+)'
    match = re.match(log_pattern, line)
    if match:
        return {
            "timestamp": match.group(1),  # Data completa
            "ip_src": match.group(2),     # Apenas o IP de origem
            "port_src": match.group(3),   # Porta de origem
            "ip_dest": match.group(4),    # IP de destino
            "port_dest": match.group(5),  # Porta de destino
            "resource": match.group(8),   # Recurso acessado
            "status": match.group(9),     # Código de status HTTP
            "size": f"{match.group(10)} bytes"  # Tamanho da requisição
        }
    return None

@app.route("/logs", methods=["GET"])
def get_logs():
    logs = []
    if os.path.exists(log_file):
        with open(log_file, "r") as f:
            for line in f:
                parsed_log = parse_log_line(line.strip())
                if parsed_log:
                    logs.append(parsed_log)
    return jsonify(logs)

@app.route("/")
def home():
    return render_template("capture.html")

if __name__ == "__main__":
    app.run(debug=True)
