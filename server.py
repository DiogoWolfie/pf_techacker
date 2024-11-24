from flask import Flask, jsonify, render_template
import os
import re

app = Flask(__name__)
log_file = "access.log"

def parse_log_line(line):
    # Regex. Tentei com tratamento de strings mas não funcionou tão bem
    log_pattern = (
        r'(?P<log_time>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d+) - (?P<timestamp>\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}\.\d+) - '
        r'(?P<ip_src>[0-9\.]+):(?P<port_src>\d+) -> (?P<ip_dest>[0-9\.]+):(?P<port_dest>\d+) - - '
        r'\[(?P<protocol>[A-Z]+)\] - (?P<size>\d+) bytes - (?P<http_method>[A-Z]+) - Status: (?P<http_status>\d+|N/A)'
    )
    match = re.match(log_pattern, line)
    if match:
        return {
            "log_time": match.group("log_time"),
            "send_time": match.group("timestamp"),
            "ip_src": match.group("ip_src"),
            "port_src": match.group("port_src"),
            "ip_dest": match.group("ip_dest"),
            "port_dest": match.group("port_dest"),
            "protocol": match.group("protocol"),
            "size": match.group("size"),
            "http_method": match.group("http_method"),
            "http_status": match.group("http_status"),
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
    print("Servidor iniciado! Acesse http://127.0.0.1:5000 para visualizar os logs.")
    app.run(debug=True)
