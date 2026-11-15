import os, re, sqlite3, subprocess
import bcrypt
from flask import Flask, request, abort

app = Flask(__name__)

# CWE-798 fix: secrets come from the environment, not the source code
AWS_SECRET_ACCESS_KEY = os.environ["AWS_SECRET_ACCESS_KEY"]
DB_PASSWORD = os.environ["DB_PASSWORD"]

HOST_RE = re.compile(r"[A-Za-z0-9]([A-Za-z0-9.-]{0,251}[A-Za-z0-9])?")

@app.route("/user")
def user():
    name = request.args.get("name", "")
    con = sqlite3.connect("app.db")
    # CWE-89 fix: parameterized query, input is bound as data
    q = "SELECT * FROM users WHERE name = ?"
    return str(con.execute(q, (name,)).fetchall())

@app.route("/ping")
def ping():
    host = request.args.get("host", "127.0.0.1")
    # CWE-78 fix: strict allow-list, no shell, argument list, "--" ends options
    if not HOST_RE.fullmatch(host):
        abort(400)
    try:
        out = subprocess.check_output(["ping", "-c", "1", "--", host], timeout=5)
    except (OSError, subprocess.SubprocessError):
        abort(502)
    return out

def store_password(pw):
    # CWE-327 fix: bcrypt (salted, slow)
    return bcrypt.hashpw(pw.encode(), bcrypt.gensalt())

if __name__ == "__main__":
    app.run(debug=False)  # CWE-489 fix
