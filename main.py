# Это вторая версия (v2.0)
from typing import Optional
from fastapi import FastAPI, Form, Cookie
from fastapi.responses import Response
import uvicorn
import hmac
import hashlib
import base64
import json


app = FastAPI()

SECRET_KEY = '313cf7183c4b7bb761b41e060590c51b5eff97dfee2426812ac83b902532902c'
PASSWORD_SALT = 'bb8fcf31d4ee66a56b96b3bc3a899e28da23e266b7e7bc0fb296795636ebdad0'


def sign_data(data: str) -> str:
    """Возращает подписанные данные data"""
    encode_b64 = base64.b64encode(data.encode()).decode()
    hech = hmac.new(
        SECRET_KEY.encode(),
        msg=data.encode(),
        digestmod=hashlib.sha256).hexdigest().upper()

    rezult = encode_b64 + '.' + hech
    return rezult


def get_login_from_signed_strint(login_signed: str) -> Optional[str]:
    """Производит проверку подписи cookis, \n
    возращает дешифрованый Логин или None"""
    login, sing = login_signed.split('.')
    login = base64.b64decode(login.encode()).decode()
    valid_login, valid_sing = sign_data(login).split('.')

    if hmac.compare_digest(valid_sing, sing):
        return login


def verification_password(login: str, password: str) -> bool:
    """Функция проверки пароля \n
    Принимает String, возращает Boolean"""

    hash_password = hashlib.sha256(
        (password + PASSWORD_SALT).encode()).hexdigest().lower()
    stored_password_hash = users[login]['password'].lower()

    return hash_password == stored_password_hash


users = {
    "viktor@user.com": {
        'name': 'Виктор',
        'password': 'f5c6c47925a04ebf711f456aeb254e5e6f7422d92c57fca939dd6be61645c98c',
        'balance': '100_000'
    },
    "petr@user.com": {
        'name': 'Петр',
        'password': '3e90d160965389d48a0033bc8f6d9dd35f89b7fa239aeba1e4d0dceaf2213358',
        'balance': '250_000'
    }
}


# создание GET запроса
@app.get('/')
def main(login: Optional[str] = Cookie(default=None)):
    login_page = open('templates/login.html').read()
    # проверка cookis
    if not login:
        return Response(login_page, media_type='text/html')
    valid_login = get_login_from_signed_strint(login)

    if not valid_login:
        response = Response(login_page, media_type='text/html')
        # response.delete_cookie(key='login')
        return response

    try:
        user = users[valid_login]
    except KeyError:  # При нарушение, она удаляется
        response = Response(login_page, media_type='text/html')
        # response.delete_cookie(key='login')
        return response
    return Response(f'Привет, {users[valid_login]["name"]} <br> Баланс: {users[valid_login]["balance"]}', media_type='text/html')


# Чтение POST запроса
@app.post('/login')
def post_s(login: str = Form(...), password: str = Form(...)):
    user = users.get(login)
    # Проверка пароля
    if not user or not verification_password(login, password):
        return Response(json.dumps({
                "success": False,
                "massage": "я вас не знаю!"
            }), media_type='application/json')

    response = Response(
        json.dumps({
            "success": True,
            "message": f"Поздравляю, {user['name']}! <br> У вас на счету: ${user['balance']}"
        }), media_type='application/json')

    # Добавление cookis авторизованному пользователю
    login_signed = sign_data(login)
    response.set_cookie(key='login', value=login_signed)
    return response


#  Запуск сервера Uvicorn  на 8080 порту
if __name__ == '__main__':
    uvicorn.run('main:app', port=8080, reload=True)
