import os
from werkzeug.utils import secure_filename

from flask import (
    Flask,
    render_template,
    request,
    jsonify,
    redirect,
    session
)

from fraud_detector import analyze_sms
import sqlite3

app = Flask(__name__)
app.secret_key = "gagan_upi_shield_ai_2026"

UPLOAD_FOLDER = os.path.join("static", "uploads")

if not os.path.exists(UPLOAD_FOLDER):
    os.makedirs(UPLOAD_FOLDER)

app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER





# Welcome Page
@app.route("/")
def home():
    return render_template("welcome.html")


# Fraud Checker API
@app.route("/check", methods=["POST"])
def check():

    if "user_id" not in session:
        return jsonify({"error": "Please login first"})

    data = request.get_json()

    sms = data.get("message", "")

    result = analyze_sms(sms)

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute(
        """
        INSERT INTO scan_history
        (user_id, message, status, risk_score)
        VALUES (?, ?, ?, ?)
        """,
        (
            session["user_id"],
            sms,
            result["status"],
            result["risk_score"]
        )
    )

    conn.commit()
    conn.close()

    return jsonify(result)


# Register Page
@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":

        name = request.form["name"]
        email = request.form["email"]
        password = request.form["password"]

        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()

        cursor.execute(
            "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
            (name, email, password)
        )

        conn.commit()
        conn.close()

        return redirect("/login")

    return render_template("register.html")


# Login Page
@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":

        email = request.form["email"]
        password = request.form["password"]

        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()

        cursor.execute(
            "SELECT * FROM users WHERE email=? AND password=?",
            (email, password)
        )

        user = cursor.fetchone()

        conn.close()

        if user:

            session["user_id"] = user[0]
            session["user_name"] = user[1]
            session["user_email"] = user[2]

            return redirect("/dashboard")

        else:
            return "Invalid Email or Password"

    return render_template("login.html")

@app.route("/history")
def history():

    if "user_id" not in session:
        return redirect("/login")

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute("""
    SELECT status, risk_score, scan_date
    FROM scan_history
    WHERE user_id=?
    ORDER BY id DESC
    """, (session["user_id"],))

    history_data = cursor.fetchall()

    conn.close()

    return render_template(
        "history.html",
        history=history_data
    )




@app.route("/profile")
def profile():

    if "user_email" not in session:
        return redirect("/login")

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    cursor.execute(
        "SELECT * FROM users WHERE email=?",
        (session["user_email"],)
    )

    user = cursor.fetchone()

    cursor.execute(
        "SELECT COUNT(*) FROM scan_history WHERE user_id=?",
        (session["user_id"],)
    )
    total_scans = cursor.fetchone()[0]

    cursor.execute(
        "SELECT COUNT(*) FROM scan_history WHERE user_id=? AND status='FRAUD'",
        (session["user_id"],)
    )
    fraud_count = cursor.fetchone()[0]

    cursor.execute(
        "SELECT COUNT(*) FROM scan_history WHERE user_id=? AND status='SUSPICIOUS'",
        (session["user_id"],)
    )
    suspicious_count = cursor.fetchone()[0]

    cursor.execute(
        "SELECT COUNT(*) FROM scan_history WHERE user_id=? AND status='SAFE'",
        (session["user_id"],)
    )
    safe_count = cursor.fetchone()[0]

    conn.close()

    security_score = max(0, 100 - (fraud_count * 10))

    return render_template(
        "profile.html",
        user=user,
        total_scans=total_scans,
        fraud_count=fraud_count,
        suspicious_count=suspicious_count,
        safe_count=safe_count,
        security_score=security_score
    )




@app.route("/logout")
def logout():

    session.clear()

    return redirect("/")



# Dashboard
@app.route("/dashboard")
def dashboard():

    if "user_id" not in session:
        return redirect("/login")

    conn = sqlite3.connect("database.db")
    cursor = conn.cursor()

    # Current User Stats
    cursor.execute(
        "SELECT COUNT(*) FROM scan_history WHERE user_id=?",
        (session["user_id"],)
    )
    total_scans = cursor.fetchone()[0]

    cursor.execute(
        "SELECT COUNT(*) FROM scan_history WHERE user_id=? AND status='FRAUD'",
        (session["user_id"],)
    )
    fraud_count = cursor.fetchone()[0]

    cursor.execute(
        "SELECT COUNT(*) FROM scan_history WHERE user_id=? AND status='SUSPICIOUS'",
        (session["user_id"],)
    )
    suspicious_count = cursor.fetchone()[0]

    cursor.execute(
        "SELECT COUNT(*) FROM scan_history WHERE user_id=? AND status='SAFE'",
        (session["user_id"],)
    )
    safe_count = cursor.fetchone()[0]

    # Recent 5 scans
    cursor.execute("""
    SELECT status, risk_score, scan_date
    FROM scan_history
    WHERE user_id=?
    ORDER BY id DESC
    LIMIT 5
    """, (session["user_id"],))

    recent_scans = cursor.fetchall()

    conn.close()

    security_score = max(0, 100 - (fraud_count * 10))

    return render_template(
        "dashboard.html",
        user_name=session["user_name"],
        total_scans=total_scans,
        fraud_count=fraud_count,
        suspicious_count=suspicious_count,
        safe_count=safe_count,
        security_score=security_score,
        recent_scans=recent_scans
    )


# Scanner Page
@app.route("/checker")
def checker():
    return render_template("checker.html")







@app.route("/upload_photo", methods=["POST"])
def upload_photo():

    if "user_id" not in session:
        return redirect("/login")

    photo = request.files["photo"]

    if photo:

        filename = secure_filename(photo.filename)

        photo.save(
            os.path.join(
                app.config["UPLOAD_FOLDER"],
                filename
            )
        )

        conn = sqlite3.connect("database.db")
        cursor = conn.cursor()

        cursor.execute(
            """
            UPDATE users
            SET photo=?
            WHERE id=?
            """,
            (
                filename,
                session["user_id"]
            )
        )

        conn.commit()
        conn.close()

    return redirect("/profile")



if __name__ == "__main__":
    app.run(debug=True)














    