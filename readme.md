# 简单的聊天服务器 
学习websocket,了解使用为主。还有很多想要实现而没有实现的功能。
### 快速使用
#### 本地运行
##### 启动flask socket后端
```bash
pip install -r requirements.txt

python3 chat_socket.py
```
##### 启动 前端页面
直接打开chat_login.html页面

#### 远程启动
##### 启动flask socket后端
```bash
pip install -r requirements.txt

python3 chat_socket.py
```
##### 启动 前端页面
修改 static/ajax_token.js 中的host和ws为自己的ip

![image](https://github.com/libaibuaidufu/chat_socket/blob/master/login.png)
![image](https://github.com/libaibuaidufu/chat_socket/blob/master/create_delete_room.png)
![image](https://github.com/libaibuaidufu/chat_socket/blob/master/chat.png)