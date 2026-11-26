import hmac
import os

import pymysql
from flask import Flask, redirect, render_template, request, session, url_for
from werkzeug.security import check_password_hash

from database import Database

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-secret-key-change-me")


def password_matches(stored, entered):
    """Сверяет введённый пароль с сохранённым в БД.

    Поддерживаются хеши werkzeug (pbkdf2:/scrypt:) и обычный текст,
    как в учебной схеме из задания.
    """
    if stored.startswith(("pbkdf2:", "scrypt:")):
        return check_password_hash(stored, entered)
    return hmac.compare_digest(stored.encode("utf-8"), entered.encode("utf-8"))


@app.route("/")
def index():
    return render_template("index.html", error=None, username="")


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")

    def fail(message):
        return render_template("index.html", error=message, username=username)

    if not username or not password:
        return fail("Заполните имя пользователя и пароль")

    db = None
    try:
        db = Database()
        user = db.get_user(username)
    except pymysql.MySQLError:
        return fail("Нет связи с базой данных. Попробуйте позже")
    except Exception:
        return fail("Ошибка при проверке данных. Попробуйте позже")
    finally:
        if db is not None:
            db.close()

    # Одно и то же сообщение для "нет пользователя" и "неверный пароль"
    if user is None or not password_matches(user["user_password"], password):
        return fail("Неверное имя пользователя или пароль")

    session["user"] = user["user_name"]
    return redirect(url_for("login_page"))


@app.route("/welcome")
def login_page():
    if "user" not in session:
        return redirect(url_for("index"))
    return render_template("login.html", username=session["user"])


@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("index"))


if __name__ == "__main__":
    app.run(debug=True)
