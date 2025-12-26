

from flask import Flask, render_template, request, send_file
from werkzeug.utils import secure_filename
import os
import json
import yaml
import jwt
import datetime
from flask import request, jsonify
from diagram_generator import generate_annotated_diagram

from threatEngine import ThreatEngine
from models import SystemModel
from UMLParser import parse_uml
from openAPI_Parser import parse_openapi
from iac_Parser import parse_iac
from source_code_Parser import parse_source_code
from flask import render_template
from flask import abort, render_template, request, redirect
from functools import wraps



from functools import wraps
from flask_login import LoginManager, login_required, current_user
from models import User
from audit import write_log
from jwt_utils import jwt_required
from datetime import timedelta
from flask import session
from flask_login import logout_user
from crypto_utils import encrypt_bytes, decrypt_bytes


from extensions import limiter
ALLOWED_EXT = {"yaml", "yml", "json", "tf", "py", "uml", "xml", "txt", "drawio"}

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXT



from flask_wtf import CSRFProtect


app = Flask(__name__)
csrf = CSRFProtect(app)
limiter.init_app(app)

app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=15)

from auth import auth_bp

UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)


@app.after_request
def make_session_permanent(response):
    session.permanent = True
    session.modified = True

    # Auto logout on inactivity
    if current_user.is_authenticated:
        last = session.get("last_activity")
        now = datetime.datetime.utcnow().timestamp()

        if last and (now - last > 900):  # 900 seconds = 15 minutes
            logout_user()
            session.clear()
            return redirect("/login")

        session["last_activity"] = now

    response = add_no_cache_headers(response)
    return response


def add_no_cache_headers(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '-1'
    return response

app.secret_key = os.environ.get("SECRET_KEY", os.urandom(24))
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# ---- Login Manager (AFTER app is created) ----
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "auth.login"

@login_manager.user_loader
def load_user(uid):
    user = User.get_by_id(uid)
    if user:
        from auth import LoginUser
        return LoginUser(user)
    return None

# ---- Register Auth Blueprint ----
app.register_blueprint(auth_bp)

# ---- RBAC Decorator ----
def role_required(role):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            if current_user.role != role:
                abort(403)
            return func(*args, **kwargs)
        return wrapper
    return decorator






# --- Helper function ---
def parse_file(file_path, parser_type, system_model):
    if parser_type == "uml":
        parse_func = parse_uml
    elif parser_type == "openapi":
        parse_func = parse_openapi
    elif parser_type == "iac":
        parse_func = parse_iac
    elif parser_type == "source":
        parse_func = parse_source_code
    else:
        return None

    model = parse_func(file_path)

    # merge parsed model into system model
    if hasattr(model, "components"):
        for c in model.components:
            system_model.add_component(c)
    if hasattr(model, "datastores"):
        for d in model.datastores:
            system_model.add_datastore(d)
    if hasattr(model, "dataflows"):
        for f in model.dataflows:
            system_model.add_dataflow(f)

    return model

# --- Routes ---
@app.route("/", methods=["GET", "POST"])
@login_required
def index():
    threats = []
    uploaded_files = []
    diagram_filename = None   # <--- ensure this ALWAYS exists

    if request.method == "POST":
        system_model = SystemModel()
        files = request.files.getlist("files[]")
        types = request.form.getlist("types[]")

        for f, t in zip(files, types):
            filename = secure_filename(f.filename)

            # Validate extension BEFORE saving
            if not allowed_file(filename):
                return "File type not allowed", 400

            path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            f.save(path)

            parse_file(path, t, system_model)
            uploaded_files.append(filename)


        engine = ThreatEngine()
        threats = engine.analyze(system_model)

        # Save encrypted report
        plain = json.dumps(threats, indent=2).encode('utf-8')
        enc_blob = encrypt_bytes(plain)
        report_path = os.path.join(app.config['UPLOAD_FOLDER'], "threat_report.json.enc")
        with open(report_path, "w", encoding="utf-8") as rpt:
            rpt.write(enc_blob)

        # Generate annotated diagram (only if there is at least one component/flow)
        try:
            if threats and (hasattr(system_model, "components") or hasattr(system_model, "dataflows")):
                diagram_path = generate_annotated_diagram(system_model, threats, out_dir=app.config['UPLOAD_FOLDER'])
                diagram_filename = os.path.basename(diagram_path)
        except Exception as e:
            # Log but do not crash the request — keep using diagram_filename = None
            print("[WARN] Diagram generation failed:", e)
            diagram_filename = None

    return render_template("index.html", threats=threats, files=uploaded_files, diagram_filename=diagram_filename)



@app.route("/download_report")
@login_required
def download_report():
    enc_path = os.path.join(app.config['UPLOAD_FOLDER'], "threat_report.json.enc")
    if not os.path.exists(enc_path):
        return "No report available", 404

    with open(enc_path, "r", encoding="utf-8") as f:
        enc_blob = f.read()

    try:
        plaintext = decrypt_bytes(enc_blob)
    except Exception as e:
        return f"Failed to decrypt report: {e}", 500

    # send as file-like object without writing plaintext to disk
    from io import BytesIO
    bio = BytesIO(plaintext)
    bio.seek(0)
    return send_file(
        bio,
        mimetype="application/json",
        as_attachment=True,
        download_name="threat_report.json"
    )


@app.route("/view_logs")
@login_required
@role_required("admin")
def view_logs():
    try:
        with open("audit.log", "r") as f:
            logs = f.readlines()
    except FileNotFoundError:
        logs = ["No logs yet."]

    return render_template("view_logs.html", logs=logs)

@app.route("/manage_rules", methods=["GET", "POST"])
@login_required
@role_required("admin")
def manage_rules():
    rules_file = "risk_rules.yaml"

    if request.method == "POST":
        new_content = request.form["content"]

        # write the updated rules
        with open(rules_file, "w") as f:
            f.write(new_content)

        write_log(current_user.username, "Updated risk rules")
        return redirect("/admin/settings")

    # Load existing rules for editing
    with open(rules_file, "r") as f:
        content = f.read()

    return render_template("manage_rules.html", content=content)



@app.route("/api/analyze", methods=["POST"])
@limiter.limit("5 per minute")
@jwt_required(role="analyst")
def api_analyze():
    if "files" not in request.files:
        return {"error": "No files uploaded"}, 400

    system_model = SystemModel()
    uploaded = request.files.getlist("files")

    for f in uploaded:
        filename = secure_filename(f.filename)
        path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        f.save(path)
        parse_file(path, "auto", system_model)

    engine = ThreatEngine()
    threats = engine.analyze(system_model)

    return {"threats": threats}

@app.route("/api/rules", methods=["GET", "POST"])
@limiter.limit("5 per minute")
@jwt_required(role="admin")
def api_rules():
    if request.method == "GET":
        with open("risk_rules.yaml") as f:
            return {"rules": f.read()}

    if request.method == "POST":
        new_rules = request.json.get("rules")
        if not new_rules:
            return {"error": "Missing rules"}, 400
        with open("risk_rules.yaml", "w") as f:
            f.write(new_rules)
        return {"status": "updated"}





@app.route("/admin/settings")
@login_required
@role_required("admin")
def admin_settings():
    write_log(current_user.username, "Opened admin dashboard")
    return render_template("admin_settings.html")


@app.route("/uploads/<path:filename>")
def download_file(filename):
    return send_file(os.path.join(app.config['UPLOAD_FOLDER'], filename))

if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=5001,
        debug=True,
        ssl_context=("cert.pem", "key.pem")
    )

