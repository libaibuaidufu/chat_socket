#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
@Time    : 2020/9/10 11:11
@File    : chat_socket.py
@author  : dfkai
@Software: PyCharm
"""

from collections import deque
from datetime import datetime

from flask import Flask, render_template, jsonify
from flask import request, current_app, g
from flask_cors import CORS
from flask_httpauth import HTTPBasicAuth
from flask_socketio import SocketIO, join_room, leave_room, emit, send
from flask_sqlalchemy import SQLAlchemy
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)
from passlib.apps import custom_app_context as pwd_context
from sqlalchemy_utils.types.choice import ChoiceType

app = Flask(__name__)
CORS(app)
# app.config['SECRET_KEY'] = str(uuid.uuid4())
app.config['SECRET_KEY'] = "dfk"
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///test.db'
app.config['CSRF_ENABLED'] = True
app.config['JSON_AS_ASCII'] = False
db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*")
room_list = []
thread_get_room_list = None

auth = HTTPBasicAuth()
room_dict = {}


def get_ip():
    return request.remote_addr


class User(db.Model):
    TYPES = [
        ('1', "超级管理员"),
        ('2', "房间管理员"),
        ('3', "小黄是狗"),
        ('4', "超级会员"),
        ('5', "普通会员"),
    ]

    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    username = db.Column(db.String(50), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(200), nullable=False)
    nickname = db.Column(db.String(50))
    role = db.Column(ChoiceType(TYPES), default="5")
    reg_time = db.Column(db.DateTime, default=datetime.now)
    reg_ip = db.Column(db.String(20), default=get_ip)
    login_time = db.Column(db.DateTime, default=datetime.now)
    login_ip = db.Column(db.String(20), default=get_ip)

    def hash_password(self, password):
        self.password_hash = pwd_context.encrypt(password)

    def verify_password(self, password):
        return pwd_context.verify(password, self.password_hash)

    def generate_auth_token(self, expiration=600):
        self.login_ip = get_ip()
        self.login_time = datetime.now()
        self.save_user()
        s = Serializer(current_app.config['SECRET_KEY'], expires_in=expiration)
        return s.dumps({'id': self.id})

    @classmethod
    def verify_auth_token(cls, token):
        '''验证 用于登陆的token'''
        s = Serializer(current_app.config['SECRET_KEY'])
        try:
            data = s.loads(token)
        except SignatureExpired:
            return None  # valid token, but expired
        except BadSignature:
            return None  # invalid token
        user = cls.get_user_by_id(data['id'])
        return user

    @staticmethod
    def get_user_by_name(username):
        user = User.query.filter_by(username=username).first()
        return user

    @staticmethod
    def get_user_by_id(user_id):
        '''
        通过数据库id获取用户信息
        :param user_id:
        :return:
        '''
        user = User.query.filter_by(id=user_id).first()
        return user

    @staticmethod
    def exist_user(username):
        user = User.query.filter_by(username=username).first()
        if user:
            return user.username
        else:
            return None

    def save_user(self):
        try:
            db.session.add(self)
            db.session.commit()
            user = self.get_user_by_name(self.username)
        except Exception as e:
            print(e)
            db.session.rollback()
            user = None
        return user


# db.drop_all()
db.create_all()


@auth.verify_password
def verify_password(username_or_token, password):
    '''
    验证用户名密码，用户名可以是token
    :param username_or_token:
    :param password:
    :return:
    '''
    user = User.verify_auth_token(username_or_token)
    if not user:
        user = User.get_user_by_name(username_or_token)
        if not user or not user.verify_password(password):
            return False
    g.user = user
    return True


@app.route("/create_default_user")
def create_default_user():
    user = User()
    user.username = "admin"
    user.nickname = "admin"
    user.role = "1"
    user.hash_password("xhsg123")
    user = user.save_user()
    if user:
        return jsonify({'msg': "注册成功", "status": "success"})
    else:
        return jsonify({'msg': "注册失败", "status": "fail"})


@app.route("/register", methods=["POST"])
def register():
    if request.method == "POST":
        username = request.json.get("username")
        password = request.json.get("password")
        role = '5'
        if username is None or password is None:
            return jsonify({"msg": "需要用户名密码", "status": "fail"}), 400  # missing arguments
        if User.exist_user(username):
            return jsonify({"msg": "该用户名已经被注册!", "status": "fail"}), 400  # existing user
        if role is None:
            return jsonify({"msg": "需要设置权限", "status": "fail"}), 400
        user = User()
        user.username = username
        user.nickname = username
        user.hash_password(password)
        user.role = role
        user = user.save_user()
        if user:
            return jsonify({'msg': "注册成功", "status": "success"})
        else:
            return jsonify({'msg': "注册失败", "status": "fail"})
    return render_template("chat_register.html")


@app.route('/user/current_user')
@auth.login_required
def get_current_user_info():
    '''获取当前用户信息'''
    user = g.user
    return jsonify({'username': user.username, "nickname": user.nickname, "role": user.role.value})


@app.route('/user/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token(600)
    return jsonify({'token': token.decode('ascii'), 'duration': 600})


@app.route("/")
@auth.login_required
def index():
    return render_template('chat_join_and_list.html', room_list=room_list)


@app.route("/join_chat")
@auth.login_required
def join_chat():
    return render_template('join_chat.html')
    # return render_template('chat_join_and_list.html',room_list=room_list)


@app.route("/chat")
@auth.login_required
def chat():
    username = request.args["username"]
    room_num = int(request.args["room_num"])
    room_name = request.args["room_name"]
    return render_template('chat.html', username=username, room_num=room_num, room_name=room_name)


@app.route("/create_room", methods=["POST", "GET"])
@auth.login_required
def on_create_room():
    if request.method == "POST":
        data = request.json
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        room_num = int(data['room_num'])
        room_name = data['room_name']
        room_num_list = [room["room_num"] for room in room_list]
        if room_num in room_num_list:
            return jsonify({'msg': "房间号已经存在了", "code": 1})
            # send({'msg': "房间号已经存在了", "code": 1})
            # emit('my_response', {'msg': "房间号已经存在了", "code": 1}, room=room_num)
        else:
            # join_room(room_num)
            room_list.append({
                "room_num": room_num,
                "room_name": room_name,
                "room_create_time": now
            })
            room_dict[str(room_num)] = deque(maxlen=100)
            return jsonify({'msg': "房间号创建成功", "code": 0})
            # send({'msg': "房间号创建成功", "code": 0})
            # emit('my_response', {'msg': "房间号创建成功", "code": 0}, room=room_num)
    else:
        return render_template("create_delete_room.html", room_list=room_list)


@app.route("/delete_room", methods=["POST", "GET"])
@auth.login_required
def on_delete_room():
    if request.method == "POST":
        data = request.json
        room_num = int(data['room_num'])
        for room in room_list:
            if room["room_num"] == room_num:
                room_list.remove(room)
                room_dict.pop(str(room_num))
                return jsonify({'msg': "房间删除成功！", "code": 0})
        return jsonify({'msg': "房间号不存在", "code": 0})
    else:
        return render_template("create_delete_room.html", room_list=room_list)


@socketio.on("get_room_list", namespace="/get_room_list")
def get_room_list():
    print("get_room_list")
    socketio.emit("get_room_list", {"room_list": room_list}, namespace="/get_room_list")


@socketio.on("disconnect", namespace="/get_room_list")
def dis_room_list():
    print("disconnect_get_room_list")
    # disconnect(namespace="/get_room_list")


#
# @socketio.on("connect", namespace="/get_room_list")
# def get_room_list():
#     print("connect_get_room_list")
#     if not thread_get_room_list:
#         socketio.start_background_task(thread_get_room_list_by_get_room_list)
#
#
#
#
# def thread_get_room_list_by_get_room_list():
#     while True:
#         print("send_get_room_list_back")
#         socketio.sleep(20)
#         socketio.emit("get_room_list", {"room_list": room_list}, namespace="/get_room_list")
#

@socketio.on('join')
def on_join(data):
    print("join")
    username = data['username']
    room_num = int(data['room_num'])
    room_num_list = [room["room_num"] for room in room_list]
    if room_num in room_num_list:
        join_room(room_num)
        emit("load_old_msg", {"data": list(room_dict[str(room_num)])}, room=room_num)
        emit('my_response', {'msg': username + ' 进来了', 'room': room_num, 'username': "系统", 'code': 0}, room=room_num)
    else:
        send({'msg': "房间号不存在", 'room': room_num, 'username': "系统", 'code': 1})
        # emit('my_response', {'msg': "房间号不存在", 'room': room_num, 'username': "系统", 'code': 1})


@socketio.on('leave')
def on_leave(data):
    print("leave")
    username = data['username']
    room_num = int(data['room_num'])
    leave_room(room_num)
    emit('my_response', {'msg': username + ' 他走了', 'room': room_num, 'username': "系统", 'code': 0}, room=room_num)


@socketio.on('chat_message')
def handle_chat_message(msg_data):
    print("chat_message")
    if str(msg_data["room_num"]) in room_dict:
        room_dict[str(msg_data["room_num"])].append(msg_data)
    else:
        room_dict[str(msg_data["room_num"])] = deque(maxlen=100)

    room_num = int(msg_data["room_num"])
    emit('my_response', msg_data, room=room_num)


if __name__ == '__main__':
    socketio.run(app, host="0.0.0.0", debug=True)
