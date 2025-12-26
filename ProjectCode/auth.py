from flask import Blueprint, render_template, request, redirect, session, url_for
from flask_login import login_user, logout_user, login_required, UserMixin, current_user
from models import User
import pyotp
from werkzeug.security import check_password_hash
import re
from flask import flash
from jwt_utils import create_jwt
from extensions import limiter


auth_bp = Blueprint('auth', __name__)

# ------------------------------
# User session wrapper
# ------------------------------
class LoginUser(UserMixin):
    def __init__(self, user):
        self.id = user.id
        self.username = user.username
        self.role = user.role
        self.mfa_secret = user.mfa_secret


# ------------------------------
# USER REGISTRATION (Analyst only)
# ------------------------------


def is_strong_password(pw):
    if len(pw) < 8:
        return False
    if not re.search(r"[A-Z]", pw):
        return False
    if not re.search(r"[a-z]", pw):
        return False
    if not re.search(r"\d", pw):
        return False
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", pw):
        return False
    return True


@auth_bp.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # Check if username already exists
        if User.exists(username):
            return "Username already exists. Please choose another one."

        # Strong password validation
        if not is_strong_password(password):
            return "Password too weak. Must be 8+ chars with uppercase, lowercase, number, special character."

        role = "analyst"
        mfa_secret = pyotp.random_base32()

        User.create(username, password, role, mfa_secret)

        # Show MFA setup page
        return render_template("show_mfa.html", secret=mfa_secret)

    return render_template("register.html")


@auth_bp.route("/api/token", methods=["POST"])
def api_token():
    data = request.json
    if not data:
        return {"error": "JSON required"}, 400

    username = data.get("username")
    password = data.get("password")
    mfa_code = data.get("mfa")

    user = User.get(username)
    if not user:
        return {"error": "User not found"}, 404

    from werkzeug.security import check_password_hash
    if not check_password_hash(user.password_hash, password):
        return {"error": "Invalid password"}, 401

    # MFA check
    totp = pyotp.TOTP(user.mfa_secret)
    if not totp.verify(mfa_code):
        return {"error": "Invalid MFA"}, 401

    # Return JWT
    token = create_jwt(user.id, user.role)
    return {"token": token}



# ------------------------------
# LOGIN (Password check only)
# ------------------------------
@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit("10/minute")
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        user = User.get(username)
        if not user:
            return "User not found"

        if not check_password_hash(user.password_hash, password):
            return "Invalid password"

        # Temporary session for MFA step
        session["pending_uid"] = user.id
        return redirect(url_for("auth.mfa_verify"))

    return render_template("login.html")


# ------------------------------
# MFA Verification (TOTP)
# ------------------------------
@auth_bp.route("/mfa", methods=["GET", "POST"])
def mfa_verify():
    if "pending_uid" not in session:
        return redirect("/login")

    user = User.get_by_id(session["pending_uid"])
    totp = pyotp.TOTP(user.mfa_secret)

    if request.method == "POST":
        code = request.form["code"]

        if totp.verify(code):
            login_user(LoginUser(user))
            session.pop("pending_uid", None)

            # Redirect based on role
            if user.role == "admin":
                return redirect("/admin/settings")
            return redirect("/")

        return "Invalid MFA code"

    return render_template("verify_mfa.html")


# ------------------------------
# LOGOUT
# ------------------------------
@auth_bp.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect("/login")
