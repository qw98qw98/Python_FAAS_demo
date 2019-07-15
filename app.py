# coding=utf-8
from eventlet import monkey_patch
from flask_cors import *

monkey_patch()
from flask import json
from flask_socketio import SocketIO, emit, send
from flask_restless import APIManager
from flask import Flask, jsonify, request, abort, url_for, render_template, blueprints
from flask import redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, current_user, login_required, logout_user
import docker
from docker.types import Mount
import os

client = docker.from_env()
app = Flask(__name__)
app.config["SECRET_KEY"] = "guessWhat"
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL", "sqlite:///" + os.path.join(app.root_path, "test.db"))
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

socketio = SocketIO(app)
db = SQLAlchemy(app)
from flask_login import config
from model import *

CORS(app, supports_credentials=True)
login_manager = LoginManager(app)

manager = APIManager(app, flask_sqlalchemy_db=db)
manager.create_api(User, methods=['GET', 'DELITE'])


@login_manager.user_loader
def load_user(user_id):
    return db.session.query(User).filter_by(id=user_id).first()  # 认证成功将此加入session,current_user


def finduser(username):
    return db.session.query(User).filter_by(username=username).first()  # 用于表单认证，根据用户名找到用户


import time
import re


def username_validate(username):
    name_match = re.compile(r"^[a-zA-Z][a-zA-Z0-9_]{4,19}$")  # 3-20个,开头必须为字母.下划线或者字母或者数字或者下划线的组合
    try:
        return name_match.match(username).group() == username
    except AttributeError:
        return False


def password_validate(password):
    password_match = re.compile(r"[a-zA-Z0-9\.,]{4,19}")  # 3-20个字母和数字或者, .的组合
    try:
        return password_match.match(password).group() == password
    except AttributeError:
        return False


import random


@app.route("/login")
def login():
    return render_template("login.html")


@app.route("/register")
def register():
    return render_template("register.html")


@app.route("/logout")
def logout():
    logout_user()
    return redirect("/index")


@app.route("/code")
def code():
    return render_template("coding.html")


def unauthorized_handler():
    return redirect(url_for("login"))


@app.route('/')
@app.route('/index')
def hello_world():
    if current_user.is_anonymous:
        return unauthorized_handler()
    print(current_user.get_id)
    return render_template("index.html", user=current_user)


@socketio.on("my event")
def show(codetext):
    socketio.emit("code_screen", codetext)


@socketio.on("response")
def debugshou(data):
    print(data);


@socketio.on('message')
def handle_message(message):
    data = json.dumps(message)
    print('received message: ' + data)


# ----------------------------Resource
@app.route("/api/login", methods=["post", "get"])
def login_message_handler():
    if request.method == 'POST':
        username = request.values.get('username')
        password = request.values.get('password')  # 从表单拉取数据
        remember = True
        alloweduser = None
        print(username + password)
        if finduser(username):
            alloweduser = finduser(username)
        else:
            abort(401)
        if username != alloweduser.username or get_md5(password) != alloweduser.password_hash:
            abort(401)
        login_user(alloweduser, remember=True) if remember else login_user(alloweduser)
        return jsonify(type="success", user_id=current_user.id, username=current_user.username)
        # if current_user.is_authenticated:
        #     return redirect("/login")
        #


@app.route("/api/user/<userid>/container",methods=["POST"])
def pythom_docker_containers(userid=None):
    if userid:
        user=load_user(userid)
        usercontainerlist=client.containers.list(all=True, filters={"name": user.username})
        contaninerIdAndStatus=[{"id":i.id,"status":i.status}for i in usercontainerlist]

        return jsonify(
            {
             "user": {
                 "username": user.username,
                 "user_id": user.id
             },
             "usercontainer": contaninerIdAndStatus
             })


@app.route("/api/code_handler", methods=["post"])
def python_code_handler():
    if request.method == "POST":
        data = json.loads(request.values.get("code"))
        filename = str(current_user.username) + "_" + str(time.time()).replace(".", 'x') + ".py"
        textfile = "G:\\Docker_trial\\pythonSrc\\"
        with open(textfile + filename, "w") as f:
            f.write(data["code"])
        command = f"python {filename}"
        mount = Mount(type="bind", target="/usr/src/app/", source="G:\\Docker_trial\\pythonSrc", read_only=True)
        container = client.containers.run(image="python:my", command=command, detach=True,
                                          auto_remove=False, remove=False, mounts=[mount], name=filename)
        time.sleep(1)
        log = container.logs()
        if isinstance(log, bytes):
            log = str(log, encoding='utf-8')
        print(log)
        show(log)
        usercontainerlist=client.containers.list(all=True, filters={"name": current_user.username})
        contaninerIdAndStatus=[{"id":i.id,"status":i.status}for i in usercontainerlist]
        return jsonify(
            log=log,
            user={
                "username": current_user.username,
                "user_id": current_user.id
            },
            usercontainers=contaninerIdAndStatus
        )
    else:
        print("wrong")
        return jsonify({"status": "wroooooong"})


@app.route("/api/regist", methods=["post", "get"])
def register_message_handler():
    # print(request.form)
    if request.method == 'POST':
        username = request.values.get("username")
        password = request.values.get('password')  # 从表单拉取数据
        if finduser(username):
            abort(401)
        if not username_validate(username) or not password_validate(password):
            abort(401)
        user = User(id=random.randint(1, 90000), username=username, password=password)
        db.session.add(user)
        print("register sucessful")
        db.session.commit()
        return jsonify(type="success", id=user.id, username=user.username)


if __name__ == '__main__':
    socketio.run(app=app, host="0.0.0.0", port="5000", debug=True)
