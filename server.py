from flask import Flask, jsonify, render_template
import os
import re

app = Flask(__name__)
log_file = "access.log"

def parse_log_line(line):
    # Regex para capturar os campos do log
    log_pattern = (
        r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2},\d+ - (?P<timestamp>\d+\.\d+) - (?P<ip_src>[0-9\.]+):(?P<port_src>\S+) -> (?P<ip_dest>[0-9\.]+):(?P<port_dest>\S+) - - '
        r'\[(?P<protocol>[A-Z]+)\] - (?P<size>\d+) bytes'
    )
    match = re.match(log_pattern, line)
    if match:
        return {
            "send_time": match.group("timestamp"),
            "ip_src": match.group("ip_src"),
            "port_src": match.group("port_src"),
            "ip_dest": match.group("ip_dest"),
            "port_dest": match.group("port_dest"),
            "protocol": match.group("protocol"),
            "size": match.group("size"),
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
