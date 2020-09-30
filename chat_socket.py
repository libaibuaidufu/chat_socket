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

from flask import Flask, render_template, jsonify, request, current_app, g,session
from flask_cors import CORS
from flask_httpauth import HTTPBasicAuth
from flask_socketio import SocketIO, join_room, leave_room, emit, disconnect
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
user_list = []
thread_get_room_list = None

auth = HTTPBasicAuth()
room_dict = {}
user_room_dict = {}


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


class UserFriend(db.Model):
    __table_args__ = (
        db.UniqueConstraint('user_id', 'friend_id', name='idx_user_friend'),  # 自己和好友联合唯一
    )
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    friend_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)

    def save_user_friend(self):
        try:
            db.session.add(self)
            db.session.commit()
        except Exception as e:
            print(e)
            db.session.rollback()

    @staticmethod
    def delete_friend(friend_id):
        try:
            user_friend = UserFriend.query.filter(UserFriend.user_id == g.user.id,
                                                  UserFriend.friend_id == friend_id).first()
            # db.session.remove() # 是移除 session
            db.session.delete(user_friend)
            db.session.commit()
            return True
        except Exception as e:
            print(e)
            db.session.rollback()
        return False


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
    print(username_or_token)
    print(password)
    user = User.verify_auth_token(username_or_token)
    if not user:
        user = User.get_user_by_name(username_or_token)
        if not user or not user.verify_password(password):
            print('token_fail')
            emit("token_fail")
            return False
    g.user = user
    return True


@app.route("/create_default_user/<string:username>")
def create_default_user(username):
    user = User()
    user.username = username
    user.nickname = username
    user.role = "1"
    user.hash_password("xhsg123")
    user = user.save_user()
    if user:
        return jsonify({'msg': "注册成功", "status": "success"})
    else:
        return jsonify({'msg': "注册失败", "status": "fail"})


@app.route("/register", methods=["POST"])
def register():
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


@app.route("/user/friend", methods=["GET", "POST"])
@auth.login_required
def get_user_friend():
    """
    查看还有列表
    新增好友
    :return:
    """
    if request.method == "POST":
        username = request.json.get("username")
        friend = User.get_user_by_name(username)
        if UserFriend.query.filter(UserFriend.user_id == g.user.id, UserFriend.friend_id == friend.id).count():
            return jsonify({"msg": "你已添加 {} 为好友".format(username)})
        if friend:
            user_friend = UserFriend()
            user_friend.user_id = g.user.id
            user_friend.friend_id = friend.id
            user_friend.save_user_friend()
            return jsonify({"msg": "添加 {} 为好友成功".format(username)})
        else:
            return jsonify({"msg": "添加 {} 失败".format(username)})
    own_friend = User.query.with_entities(User.username).filter(
        User.id.in_(UserFriend.query.with_entities(UserFriend.friend_id).filter(UserFriend.user_id == g.user.id))).all()
    friend_list = [friend.username for friend in own_friend]
    return jsonify({"friend": friend_list})


@app.route("/user/friend/search/<string:username>", methods=["GET"])
@auth.login_required
def user_friend_search(username):
    """
    搜索 用户
    :param username:
    :return:
    """
    user_list = User.query.filter(User.username.contains(username)).all()
    if user_list:
        data = []
        for user in user_list:
            data.append({'username': user.username, "nickname": user.nickname, "role": user.role.value})
        return jsonify({"data": data, "msg": ""})
    return jsonify({"msg": "未搜索到 {}".format(username), "data": []})


@app.route("/user/friend/_delete", methods=["POST"])
@auth.login_required
def user_friend_delete():
    """
    删除好友
    :return:
    """
    username = request.json.get("username")
    friend = User.get_user_by_name(username)
    if friend:
        status = UserFriend.delete_friend(friend.id)
        if status:
            return jsonify({"msg": "删除成功"})
        return jsonify({"msg": "删除失败"})
    return jsonify({"msg": "找不到好友"})


@app.route('/user/current_user')
@auth.login_required
def get_current_user_info():
    '''获取当前用户信息'''
    user = g.user
    return jsonify({'username': user.username, "nickname": user.nickname, "role": user.role.value})


@app.route('/user/token')
@auth.login_required
def get_auth_token():
    token = g.user.generate_auth_token(5)
    return jsonify({'token': token.decode('ascii'), 'duration': 600})


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

# from functools import wraps
# def socket_login(fn):
#     @wraps(fn)
#     def wrapped(*args,**kwargs):
#         user_sid = [user.sid for user in user_list]
#         if  request.sid in user_sid:
#             user_list


@socketio.on("create_room", namespace="/get_user_room")
@auth.login_required
def on_create_room(data):
    print("on_create_room")
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    room_num = int(data['room_num'])
    room_name = data['room_name']
    room_num_list = [room["room_num"] for room in room_list]
    if room_num in room_num_list:
        emit('layer_msg', {'msg': "房间号已经存在了", "code": 1})
    else:
        room_list.append({
            "room_num": room_num,
            "room_name": room_name,
            "room_create_time": now
        })
        room_dict[str(room_num)] = deque(maxlen=100)
        emit('layer_msg', {'msg': "房间号创建成功", "code": 0})


@socketio.on("delete_room", namespace="/get_user_room")
@auth.login_required
def on_delete_room(data):
    print("on_delete_room")
    room_num = int(data['room_num'])
    if room_list:
        for room in room_list:
            if room["room_num"] == room_num:
                room_list.remove(room)
                room_dict.pop(str(room_num))
                emit('layer_msg', {'msg': "房间删除成功!", "code": 1})
    else:
        emit('layer_msg', {'msg': "房间号不存在", "code": 0})


@socketio.on("get_room_list", namespace="/get_user_room")
@auth.login_required
def on_get_room_list():
    print("on_get_room_list")
    emit("get_room_list", {"room_list": room_list})


@socketio.on("disconnect", namespace="/get_user_room")
def on_dis_room_list():
    print("on_dis_room_list")
    disconnect()


@socketio.on("get_user_friend", namespace="/get_user_room")
@auth.login_required
def on_get_user_friend():
    print("on_get_user_friend")
    own_friend = User.query.with_entities(User.username).filter(
        User.id.in_(UserFriend.query.with_entities(UserFriend.friend_id).filter(UserFriend.user_id == g.user.id))).all()
    friend_list = [{"username": friend.username} for friend in own_friend]
    emit("get_user_friend", {"friend_list": friend_list})


@socketio.on("add_friend", namespace="/get_user_room")
@auth.login_required
def on_add_friend(data):
    print("on_add_friend")
    username = data.get("username")
    friend = User.get_user_by_name(username)
    if UserFriend.query.filter(UserFriend.user_id == g.user.id, UserFriend.friend_id == friend.id).count():
        emit('layer_msg', {'msg': "你已添加 {} 为好友".format(username), "code": 0})
        return False
    if friend:
        user_friend = UserFriend()
        user_friend.user_id = g.user.id
        user_friend.friend_id = friend.id
        user_friend.save_user_friend()
        emit('layer_msg', {'msg': "添加 {} 为好友成功".format(username), "code": 0})
        return False
    else:
        emit('layer_msg', {'msg': "添加 {} 失败".format(username), "code": 0})
        return False


@socketio.on("delete_friend", namespace="/get_user_room")
@auth.login_required
def on_delete_friend(data):
    username = data.get("username")
    friend = User.get_user_by_name(username)
    if friend:
        status = UserFriend.delete_friend(friend.id)
        if status:
            emit('layer_msg', {'msg': "删除成功", "code": 1})
            return False
        emit('layer_msg', {'msg': "删除失败", "code": 0})
        return False
    emit('layer_msg', {'msg': "找不到好友", "code": 0})
    return False


@socketio.on('join', namespace="room")
def on_join(data):
    print("on_join")
    username = data['username']
    room_num = int(data['room_num'])
    room_num_list = [room["room_num"] for room in room_list]
    if room_num in room_num_list:
        join_room(room_num)
        emit("load_old_msg", {"data": list(room_dict[str(room_num)])})
        emit('my_response', {'msg': username + ' 进来了', 'room': room_num, 'username': "系统", 'code': 0}, room=room_num)
    else:
        emit('my_response', {'msg': "房间号不存在", 'room': room_num, 'username': "系统", 'code': 1})


@socketio.on('leave', namespace="room")
def on_leave(data):
    print("on_leave")
    username = data['username']
    room_num = int(data['room_num'])
    leave_room(room_num)
    emit('my_response', {'msg': username + ' 他走了', 'room': room_num, 'username': "系统", 'code': 0}, room=room_num)


@socketio.on('chat_message', namespace="room")
def handle_chat_message(msg_data):
    print("chat_message")
    if str(msg_data["room_num"]) in room_dict:
        room_dict[str(msg_data["room_num"])].append(msg_data)
    else:
        room_dict[str(msg_data["room_num"])] = deque(maxlen=100)

    room_num = int(msg_data["room_num"])
    emit('my_response', msg_data, room=room_num)


@socketio.on("join", namespace="one_to_one")
def on_join_by_one_to_one(data):
    pass


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
if __name__ == '__main__':
    socketio.run(app, host="0.0.0.0", debug=True)
