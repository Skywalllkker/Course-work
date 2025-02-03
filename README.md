# Course-work
from fastapi import FastAPI, HTTPException, Header, Depends
from pydantic import BaseModel
import hashlib
import time
from typing import Optional, Dict, List
from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from typing import Dict
import secrets

app = FastAPI()

# Имитация базы данных пользователей
users_db: Dict[str, Dict[str, str]] = {}
request_history: List[Dict] = []


class User(BaseModel):
    username: str
    password: str

class LoginRequest(BaseModel):
    username: str
    password: str

class ChangePasswordRequest(BaseModel):
    old_password: str
    new_password: str

class EncryptRequest(BaseModel):
    message: str
    key: int

class DecryptRequest(BaseModel):
    message: str
    key: int

def create_token(username: str) -> str:
    timestamp = int(time.time())
    return hashlib.sha256(f"{username}{timestamp}".encode()).hexdigest()

def save_to_history(endpoint: str, payload: dict, response: dict, status_code: int):
    request_history.append({
        "endpoint": endpoint,
        "payload": payload,
        "response": response,
        "status_code": status_code
    })

def authenticate_user(x_api_token: Optional[str] = Header(None)) -> str:
    for username, data in users_db.items():
        if data.get("token") == x_api_token:
            return username
    raise HTTPException(status_code=403, detail="Ошибка аутентификации")

def scytale_encrypt(message: str, key: int) -> str:
    encrypted = [''] * key
    for i, char in enumerate(message):
        encrypted[i % key] += char
    return ''.join(encrypted)

def scytale_decrypt(encrypted_message: str, key: int) -> str:
    num_cols = -(-len(encrypted_message) // key)
    decrypted = [''] * num_cols
    index = 0
    for i in range(key):
        for j in range(num_cols):
            if index < len(encrypted_message):
                decrypted[j] += encrypted_message[index]
                index += 1
    return ''.join(decrypted)

@app.post("/register")
def register(user: User):
    if user.username in users_db:
        raise HTTPException(status_code=400, detail="Пользователь уже существует")
    hashed_password = hashlib.sha256(user.password.encode()).hexdigest()
    token = create_token(user.username)
    users_db[user.username] = {"password": hashed_password, "token": token}
    response = {"message": "Пользователь зарегистрирован успешно", "token": token}
    save_to_history("/register", user.dict(), response, 200)
    return response

@app.post("/login")
def login(request: LoginRequest):
    user = users_db.get(request.username)
    if not user or user["password"] != hashlib.sha256(request.password.encode()).hexdigest():
        raise HTTPException(status_code=400, detail="Неверное имя пользователя или пароль")
    user["token"] = create_token(request.username)
    response = {"token": user["token"]}
    save_to_history("/login", request.dict(), response, 200)
    return response

@app.post("/encrypt")
def encrypt(request: EncryptRequest, username: str = Depends(authenticate_user)):
    encrypted_message = scytale_encrypt(request.message, request.key)
    response = {"encrypted_message": encrypted_message}
    save_to_history("/encrypt", request.dict(), response, 200)
    return response

@app.post("/decrypt")
def decrypt(request: DecryptRequest, username: str = Depends(authenticate_user)):
    decrypted_message = scytale_decrypt(request.message, request.key)
    response = {"decrypted_message": decrypted_message}
    save_to_history("/decrypt", request.dict(), response, 200)
    return response

@app.post("/change_password")
def change_password(request: ChangePasswordRequest, username: str = Depends(authenticate_user)):
    hashed_old_password = hashlib.sha256(request.old_password.encode()).hexdigest()
    if users_db[username]["password"] != hashed_old_password:
        raise HTTPException(status_code=400, detail="Старый пароль неверен")
    users_db[username]["password"] = hashlib.sha256(request.new_password.encode()).hexdigest()
    response = {"message": "Пароль успешно изменен"}
    save_to_history("/change_password", request.dict(), response, 200)
    return response

@app.get("/history")
def get_history():
    return request_history

@app.delete("/history")
def clear_history():
    request_history.clear()
    return {"message": "История очищена"}


import requests
import hashlib
import time

BASE_URL = "http://127.0.0.1:8000"  # Адрес сервера FastAPI

# Глобальная переменная для хранения истории запросов и токена
request_history = []
TOKEN = None  # Теперь токен сохраняется после входа
USERNAME = None  # Добавлено сохранение имени пользователя

def create_token():
    """Генерация токена на основе текущего времени"""
    timestamp = int(time.time())
    return hashlib.sha256(str(timestamp).encode()).hexdigest()

def save_to_history(endpoint, payload, response):
    """Сохранение запроса и ответа в историю"""
    request_history.append({
        "endpoint": endpoint,
        "payload": payload,
        "response": response.json() if response.status_code == 200 else response.text,
        "status_code": response.status_code
    })

def register_user():
    """Регистрация нового пользователя"""
    username = input("Введите имя пользователя: ")
    password = input("Введите пароль: ")
    payload = {"username": username, "password": password}
    response = requests.post(f"{BASE_URL}/register", json=payload)
    save_to_history("/register", payload, response)

    if response.status_code == 200:
        print("✅ Регистрация успешна:", response.json())
    else:
        print("❌ Ошибка:", response.status_code, response.text)

def login_user():
    """Авторизация пользователя"""
    global TOKEN, USERNAME
    username = input("Введите имя пользователя: ")
    password = input("Введите пароль: ")
    payload = {"username": username, "password": password}
    response = requests.post(f"{BASE_URL}/login", json=payload)
    save_to_history("/login", payload, response)

    if response.status_code == 200:
        TOKEN = response.json()["token"]  # Сохраняем токен
        USERNAME = username  # Сохраняем имя пользователя
        print("✅ Вход выполнен успешно!")
    else:
        print("❌ Ошибка:", response.status_code, response.text)

def change_password():
    """Изменение пароля пользователя"""
    if TOKEN is None:
        print("❌ Ошибка: Сначала войдите в систему!")
        return

    old_password = input("Введите старый пароль: ")
    new_password = input("Введите новый пароль: ")
    headers = {"X-API-Token": TOKEN}
    payload = {"username": USERNAME, "old_password": old_password, "new_password": new_password}

    response = requests.post(f"{BASE_URL}/change_password", json=payload, headers=headers)
    save_to_history("/change_password", payload, response)

    if response.status_code == 200:
        print("✅ Пароль успешно изменён.")
    else:
        print(f"❌ Ошибка: {response.status_code} {response.text}")


def login_user():
    """Авторизация пользователя"""
    global TOKEN, USERNAME
    username = input("Введите имя пользователя: ")
    password = input("Введите пароль: ")
    payload = {"username": username, "password": password}

    response = requests.post(f"{BASE_URL}/login", json=payload)
    save_to_history("/login", payload, response)

    if response.status_code == 200:
        TOKEN = response.json()["token"]  # Сохраняем токен
        USERNAME = username  # Сохраняем имя пользователя
        print("✅ Вход выполнен успешно! Ваш токен:", TOKEN)
    else:
        print("❌ Ошибка:", response.status_code, response.text)

def encrypt_message():
    """Шифрование текста методом скитала"""
    global TOKEN  # Убедитесь, что используем глобальную переменную TOKEN
    if TOKEN is None:
        print("❌ Ошибка: Сначала войдите в систему!")
        return

    message = input("Введите текст для шифрования: ")
    key = int(input("Введите ключ (число строк): "))

    headers = {"X-API-Token": TOKEN}
    payload = {"message": message, "key": key}

    print(f"🔍 Отправляем запрос с токеном: {TOKEN}")  # DEBUG вывод токена

    response = requests.post(f"{BASE_URL}/encrypt", json=payload, headers=headers)
    save_to_history("/encrypt", payload, response)

    if response.status_code == 200:
        print("🔒 Зашифрованное сообщение:", response.json()["encrypted_message"])
    else:
        print(f"❌ Ошибка: {response.status_code} {response.text}")


def decrypt_message():
    """Дешифрование текста методом скитала"""
    if TOKEN is None:
        print("❌ Ошибка: Сначала войдите в систему!")
        return

    message = input("Введите текст для дешифрования: ")
    key = int(input("Введите ключ (число строк): "))
    headers = {"X-API-Token": TOKEN}
    payload = {"username": USERNAME, "message": message, "key": key}
    response = requests.post(f"{BASE_URL}/decrypt", json=payload, headers=headers)
    save_to_history("/decrypt", payload, response)

    if response.status_code == 200:
        print("🔓 Дешифрованное сообщение:", response.json()["decrypted_message"])
    else:
        print("❌ Ошибка:", response.status_code, response.text)

def show_request_history():
    """Показ истории запросов"""
    if not request_history:
        print("📜 История запросов пуста.")
    else:
        for i, entry in enumerate(request_history, 1):
            print(f"Запрос {i}:")
            print("  🔗 Эндпоинт:", entry["endpoint"])
            print("  📤 Данные запроса:", entry["payload"])
            print("  📥 Ответ:", entry["response"])
            print("  🔢 Код статуса:", entry["status_code"])

def clear_request_history():
    """Очистка истории запросов"""
    global request_history
    request_history = []
    print("✅ История запросов очищена.")

def main_menu():
    while True:
        print("\n📌 Выберите команду:")
        print("1️⃣ - Авторизация")
        print("2️⃣ - Регистрация")
        print("3️⃣ - Шифрование сообщения")
        print("4️⃣ - Дешифрование сообщения")
        print("5️⃣ - Сменить пароль")
        print("6️⃣ - Показать историю запросов")
        print("7️⃣ - Очистить историю запросов")
        print("8️⃣ - Выход")

        choice = input("Введите номер команды: ")

        if choice == "1":
            login_user()
        elif choice == "2":
            register_user()
        elif choice == "3":
            encrypt_message()  # ДОЛЖНО БЫТЬ ОПРЕДЕЛЕНО ВЫШЕ
        elif choice == "4":
            decrypt_message()
        elif choice == "5":
            change_password()
        elif choice == "6":
            show_request_history()
        elif choice == "7":
            clear_request_history()
        elif choice == "8":
            print("👋 Выход из программы.")
            break
        else:
            print("❌ Ошибка: Неверная команда. Попробуйте снова.")

# Запускаем меню только если выполняем скрипт напрямую
if __name__ == "__main__":
    main_menu()


import requests
from fastapi.testclient import TestClient
from main import app

client = TestClient(app)

USERNAME = "testuser"
PASSWORD = "testpassword"
NEW_PASSWORD = "newpassword"
BASE_URL = "http://127.0.0.1:8000"

def test_register():
    response = client.post("/register", json={"username": USERNAME, "password": PASSWORD})
    assert response.status_code in [200, 400]

def test_login():
    global TOKEN
    response = client.post("/login", json={"username": USERNAME, "password": PASSWORD})
    assert response.status_code == 200
    TOKEN = response.json()["token"]

def test_encrypt():
    headers = {"X-API-Token": TOKEN}
    response = client.post("/encrypt", json={"message": "hello", "key": 3}, headers=headers)
    assert response.status_code == 200
    global ENCRYPTED_MESSAGE
    ENCRYPTED_MESSAGE = response.json()["encrypted_message"]

def test_decrypt():
    headers = {"X-API-Token": TOKEN}
    response = client.post("/decrypt", json={"message": ENCRYPTED_MESSAGE, "key": 3}, headers=headers)
    assert response.status_code == 200
    assert response.json()["decrypted_message"] == "hello"

def test_change_password():
    headers = {"X-API-Token": TOKEN}
    response = client.post("/change_password", json={"old_password": PASSWORD, "new_password": NEW_PASSWORD}, headers=headers)
    assert response.status_code == 200

def test_login_with_new_password():
    global TOKEN
    response = client.post("/login", json={"username": USERNAME, "password": NEW_PASSWORD})
    assert response.status_code == 200
    TOKEN = response.json()["token"]

    








    
