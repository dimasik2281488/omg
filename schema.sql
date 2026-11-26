-- MySQL
CREATE DATABASE IF NOT EXISTS flask_auth;
USE flask_auth;

CREATE TABLE IF NOT EXISTS users (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    user_name     VARCHAR(64)  NOT NULL UNIQUE,
    user_password VARCHAR(255) NOT NULL
);

-- Тестовый пользователь
INSERT INTO users (user_name, user_password)
VALUES ('admin', '123456789');
