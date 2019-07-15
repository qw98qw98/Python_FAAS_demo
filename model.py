from app import db
from flask_login import UserMixin
from hashlib import md5
from flask_restless import APIManager


def get_md5(password):
    hash = md5((password + "济大蔡徐坤").encode("utf-8"))
    return hash.hexdigest()


class User(db.Model, UserMixin):
    def __init__(self, id, username, password):
        self.id = id
        self.username = username
        self.password_hash = get_md5(password)

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(20), unique=True)
    password_hash = db.Column(db.String(40))


db.create_all()

