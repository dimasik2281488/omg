import os

import pymysql
from pymysql.cursors import DictCursor


class Database:
    """Инкапсулирует работу с MySQL: подключение, курсор, запросы, закрытие."""

    def __init__(self):
        # Настройки берутся из переменных окружения (или значения по умолчанию)
        self.connection = pymysql.connect(
            host=os.environ.get("DB_HOST", "localhost"),
            port=int(os.environ.get("DB_PORT", "3306")),
            user=os.environ.get("DB_USER", "root"),
            password=os.environ.get("DB_PASSWORD", ""),
            database=os.environ.get("DB_NAME", "flask_auth"),
            charset="utf8mb4",
            cursorclass=DictCursor,   # строки возвращаются словарями
            connect_timeout=5,
        )
        self.cursor = self.connection.cursor()

    def get_user(self, username):
        """Возвращает запись из users (dict) или None, если пользователя нет."""
        # %s - параметр запроса: защита от SQL-инъекций
        self.cursor.execute(
            "SELECT id, user_name, user_password FROM users WHERE user_name = %s",
            (username,),
        )
        return self.cursor.fetchone()

    def create_user(self, name, password):
        """Добавляет пользователя в users и возвращает его id.

        Если имя занято, pymysql выбросит IntegrityError (UNIQUE по user_name).
        """
        with self.connection.cursor() as cur:
            cur.execute(
                "INSERT INTO users (user_name, user_password) VALUES (%s, %s)",
                (name, password),
            )
        self.connection.commit()   # без commit запись не сохранится
        return cur.lastrowid

    def close(self):
        """Закрывает курсор и соединение."""
        self.cursor.close()
        self.connection.close()

    # поддержка конструкции with Database() as db:
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
