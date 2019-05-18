# coding=utf-8
from eventlet import monkey_patch
monkey_patch()
import json
from flask_socketio import SocketIO,emit,send
from flask import Flask,jsonify,request,abort,url_for,render_template
from flask import redirect
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager,login_user,current_user,login_required,logout_user
import docker
from docker.types import Mount
client=docker.from_env()
app = Flask(__name__)
app.config["SECRET_KEY"]="guessWhat"
import os
app.config["SQLALCHEMY_DATABASE_URI"]=os.getenv("DATABASE_URL","sqlite:///"+os.path.join(app.root_path,"test.db"))
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"]=False
socketio=SocketIO(app)
db=SQLAlchemy(app)
from flask_login import config
login_manager=LoginManager(app)
from model import *
@login_manager.user_loader
def load_user(user_id):
    return db.session.query(User).filter_by(id=user_id).first()#认证成功将此加入session,current_user
def finduser(username):
    return db.session.query(User).filter_by(username=username).first()#用于表单认证，根据用户名找到用户
@app.route("/login_message",methods=["post"])
def login_message_handler():
    # print(request.form)
    username=request.form["username"]
    password=request.form["password"]#从表单拉取数据
    remember=request.form.get("remember","false")#默认为flase,若存在参数一定为true
    alloweduser=None
    if finduser(username):
        alloweduser=finduser(username)
    else:
        abort(401)
    # print(alloweduser)
    # print(alloweduser.username)
    # print(alloweduser.password_hash)
    # print("认证失败?:"+str(username != alloweduser.username or get_md5(password)!=alloweduser.password_hash))
    if username != alloweduser.username or get_md5(password)!=alloweduser.password_hash:
        abort(401)
    if current_user.is_authenticated:
        return redirect("/login")
    print("login sucessful")
    login_user(alloweduser,remember=True) if remember else login_user(alloweduser)
    return redirect("/index")
import time
@app.route("/code/code_handler",methods=["post"])
def python_code_handler():
    print(request.method)
    if request.method=="POST":
        data=json.loads(request.form.get("data"))
        # print(data["code"])
        filename=current_user.username+str(time.time()).replace(".",'x')+".py"
        textfile="G:\\Docker_trial\\pythonSrc\\"
        with open(textfile+filename, "w") as f:
            f.write(data["code"])
        command=f"python {filename}"
        mount=Mount(type="bind",target="/usr/src/app/",source="G:\\Docker_trial\\pythonSrc",read_only=True)
        container=client.containers.run(image="python:my",command=command,detach=True,
                                        auto_remove=False,remove=False,mounts=[mount])
        time.sleep(1)
        log=container.logs()
        if isinstance(log, bytes):
            log=str(log, encoding='utf-8')
        print(log)
        show(log)
        return jsonify({"status":log})
    else:
        print("wrong")
        return jsonify({"status":"wroooooong"})
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
        return password_match.match(password).group()==password
    except AttributeError:
        return False
import random
@app.route("/register_message",methods=["post"])
def register_message_handler():
    # print(request.form)
    username=request.form["username"]
    password=request.form["password"]#从表单拉取数据
    if finduser(username):
        abort(401)
    if not username_validate(username) or not password_validate(password):
        abort(401)
    # print(username)
    # print(password)
    user=User(id=random.randint(1,90000),username=username,password=password)
    db.session.add(user)
    print("register sucessful")
    db.session.commit()
    return redirect(url_for("login"))
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
    print(f"是否认证{current_user.is_authenticated}")
    print(f"是否active{current_user.is_active}" )
    print(f"是否匿名用户{current_user.is_anonymous}" )
    if current_user.is_anonymous:
        return unauthorized_handler()
    print(current_user.get_id)
    return render_template("index.html", user=current_user)

@socketio.on("my event")
def show(codetext):
    socketio.emit("code_screen",codetext)

@socketio.on("response")
def debugshou(data):
    print(data);

@socketio.on('message')
def handle_message(message):
    data=json.dumps(message)
    print('received message: ' + data)
if __name__ == '__main__':
    socketio.run(app=app,host="0.0.0.0",port="5000",debug=True)