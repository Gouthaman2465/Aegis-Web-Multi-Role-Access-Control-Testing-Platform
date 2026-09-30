"""Deliberately vulnerable Flask web application serving as the Aegis-Web test oracle."""

from datetime import datetime, timezone
import os
import uuid
from flask import (
    Flask,
    request,
    jsonify,
    render_template,
    redirect,
    url_for,
    make_response,
)

USERS = {
    1: {
        "id": 1,
        "username": "alice",
        "email": "alice@lab.test",
        "password": "alice-pass",
        "role": "user",
        "order_id": 1,
    },
    2: {
        "id": 2,
        "username": "bob",
        "email": "bob@lab.test",
        "password": "bob-pass",
        "role": "user",
        "order_id": 2,
    },
    3: {
        "id": 3,
        "username": "admin",
        "email": "admin@lab.test",
        "password": "admin-pass",
        "role": "admin",
        "order_id": 3,
    },
}

ORDERS = {
    1: {"id": 1, "user_id": 1, "item": "Blue Mug", "address": "12 Alice Street"},
    2: {"id": 2, "user_id": 2, "item": "Red Lamp", "address": "34 Bob Road"},
    3: {"id": 3, "user_id": 3, "item": "Desk", "address": "1 Admin Plaza"},
}

USER_TOKENS = {
    1: "token_alice_secret_token_val_111",
    2: "token_bob_secret_token_val_222",
    3: "token_admin_secret_token_val_333",
}

TOKEN_TO_USER = {tok: uid for uid, tok in USER_TOKENS.items()}

# In-memory session store mapping session_id -> user_id
SESSIONS: dict[str, int] = {}


def _get_cookie_user():
    """Retrieve the authenticated user dict from session cookie 'sid'."""
    sid = request.cookies.get("sid")
    if not sid or sid not in SESSIONS:
        return None
    user_id = SESSIONS[sid]
    return USERS.get(user_id)


def _get_bearer_user():
    """Retrieve the authenticated user dict from Authorization: Bearer <token>."""
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None
    token = auth_header[len("Bearer ") :].strip()
    user_id = TOKEN_TO_USER.get(token)
    if not user_id:
        return None
    return USERS.get(user_id)


def create_app():
    """Application factory for the vulnerable lab target."""
    app = Flask(__name__)
    app.config["SECRET_KEY"] = "lab-secret-key-for-testing"

    # Pre-populate static sessions for predictable curl verification
    SESSIONS["session_alice"] = 1
    SESSIONS["session_bob"] = 2
    SESSIONS["session_admin"] = 3

    @app.route("/")
    def index():
        return redirect(url_for("login"))

    @app.route("/login", methods=["GET", "POST"])
    def login():
        if request.method == "POST":
            username = request.form.get("username", "").strip()
            password = request.form.get("password", "").strip()

            target_user = None
            for u in USERS.values():
                if u["username"] == username and u["password"] == password:
                    target_user = u
                    break

            if target_user:
                sid = f"sid_{uuid.uuid4().hex}"
                SESSIONS[sid] = target_user["id"]
                resp = make_response(redirect(url_for("dashboard")))
                resp.set_cookie("sid", sid, httponly=True, samesite="Lax")
                return resp

            return render_template("login.html", error="Invalid username or password."), 200

        return render_template("login.html", error=None)

    @app.route("/logout")
    def logout():
        sid = request.cookies.get("sid")
        if sid and sid in SESSIONS:
            del SESSIONS[sid]
        resp = make_response(redirect(url_for("login")))
        resp.delete_cookie("sid")
        return resp

    @app.route("/dashboard")
    def dashboard():
        user = _get_cookie_user()
        if not user:
            return redirect(url_for("login"))
        return render_template("dashboard.html", user=user)

    # BUG: HORIZONTAL ACCESS - Missing ownership check on order
    @app.route("/orders/<int:order_id>")
    def get_order_html(order_id):
        user = _get_cookie_user()
        if not user:
            return redirect(url_for("login"))
        order = ORDERS.get(order_id)
        if not order:
            return "Order not found", 404
        return render_template("order.html", order=order)

    # BUG: VERTICAL ACCESS - Regular users can reach admin user directory
    @app.route("/admin/users")
    def admin_users():
        user = _get_cookie_user()
        if not user:
            return redirect(url_for("login"))
        return render_template("admin_users.html", users=list(USERS.values()))

    # BUG: UNAUTHENTICATED ACCESS - Sensitive config exposed without any auth
    @app.route("/api/internal/config")
    def api_config():
        return jsonify({
            "env": "lab",
            "db_password": "lab-secret-not-real",
            "feature_flags": ["v2", "beta"],
        })

    # BUG: HORIZONTAL ACCESS - Profile endpoint does not verify requesting token matches requested id
    @app.route("/api/profile/<int:user_id>")
    def api_profile(user_id):
        user = _get_bearer_user()
        if not user:
            return jsonify({"error": "Unauthorized"}), 401
        target = USERS.get(user_id)
        if not target:
            return jsonify({"error": "User not found"}), 404
        return jsonify({
            "id": target["id"],
            "username": target["username"],
            "email": target["email"],
            "role": target["role"],
        })

    # SAFE: Correct ownership check on JSON order endpoint
    @app.route("/api/orders/<int:order_id>")
    def api_order(order_id):
        user = _get_bearer_user()
        if not user:
            return jsonify({"error": "Unauthorized"}), 401
        order = ORDERS.get(order_id)
        if not order:
            return jsonify({"error": "Not found"}), 404
        if order["user_id"] != user["id"]:
            return jsonify({"error": "Forbidden - You do not own this order"}), 403
        return jsonify({
            "id": order["id"],
            "item": order["item"],
            "address": order["address"],
        })

    # SAFE: Correct admin check on stats endpoint
    @app.route("/api/admin/stats")
    def api_admin_stats():
        user = _get_bearer_user()
        if not user:
            return jsonify({"error": "Unauthorized"}), 401
        if user["role"] != "admin":
            return jsonify({"error": "Forbidden - Administrator access required"}), 403
        return jsonify({
            "total_users": len(USERS),
            "active_sessions": len(SESSIONS),
            "system_health": "optimal",
        })

    # SAFE: Exchanges cookie session for bearer token
    @app.route("/api/token")
    def api_token():
        user = _get_cookie_user()
        if not user:
            return jsonify({"error": "Unauthorized"}), 401
        return jsonify({"token": USER_TOKENS[user["id"]]})

    # SAFE: Current authenticated user details
    @app.route("/api/me")
    def api_me():
        user = _get_bearer_user()
        if not user:
            return jsonify({"error": "Unauthorized"}), 401
        return jsonify({
            "id": user["id"],
            "username": user["username"],
            "email": user["email"],
            "role": user["role"],
        })

    # SAFE: Current user notifications with dynamic timestamp
    @app.route("/api/notifications")
    def api_notifications():
        user = _get_bearer_user()
        if not user:
            return jsonify({"error": "Unauthorized"}), 401
        return jsonify({
            "notifications": [
                {
                    "id": 101,
                    "message": f"Welcome {user['username']}, your account is active.",
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                }
            ]
        })

    # SAFE: Public catalog of products (no sensitive terms)
    @app.route("/api/products")
    def api_products():
        return jsonify([
            {"id": 1, "name": "Standard Widget", "price": 19.99},
            {"id": 2, "name": "Super Gizmo", "price": 49.99},
        ])

    # -------------------------------------------------------------
    # Stage 2 Planted Test Issues
    # -------------------------------------------------------------
    @app.route("/.git/HEAD")
    def git_head():
        return "ref: refs/heads/main\n", 200, {"Content-Type": "text/plain"}

    @app.route("/.env")
    def env_file():
        return "APP_KEY=lab-not-a-real-key\nDB_PASS=fake-pass-not-real\n", 200, {"Content-Type": "text/plain"}

    @app.route("/api/cors-reflect")
    def api_cors_reflect():
        origin = request.headers.get("Origin", "*")
        resp = jsonify({"status": "cors-test-endpoint"})
        resp.headers["Access-Control-Allow-Origin"] = origin
        resp.headers["Access-Control-Allow-Credentials"] = "true"
        return resp

    @app.route("/redirect")
    def open_redirect():
        next_url = request.args.get("next") or request.args.get("url") or "/"
        return redirect(next_url, code=302)

    @app.route("/api/legacy/export")
    def api_legacy_export():
        user = _get_bearer_user()
        if not user:
            return jsonify({"error": "Unauthorized"}), 401
        # Bug: VERTICAL - exposes all user details without admin role check
        return jsonify({
            "export_version": "1.0",
            "users": [
                {"id": u["id"], "username": u["username"], "email": u["email"], "role": u["role"]}
                for u in USERS.values()
            ]
        })

    return app


if __name__ == "__main__":
    app = create_app()
    app.run(host="0.0.0.0", port=5001, debug=False)
