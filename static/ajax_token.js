(function () {
    var chat = {
        isRefreshing: true,
        subscribers: [],
        // host: "http://121.199.27.219:5000",
        // ws: "ws://121.199.27.219:5000",
		host: "http://127.0.0.1:5000",
        ws: "ws://127.0.0.1:5000",
        get_token:function(){
            var token = sessionStorage.getItem("token");
            var auth = window.btoa(token + ":" + "*");
            return auth
        },
        default_ajax: function (options, callback) {
            var token = sessionStorage.getItem("token");
            var auth = window.btoa(token + ":" + "*");
            options.headers = {
                "Authorization": "Basic " + auth
            }
            options.success = function (response) {
                callback(response)
            }
            options.error = function (requestObject, error, errorThrown) {
                var res = requestObject.responseJSON;
                if (requestObject.status === 401) {
                    // 刷新token的函数,这需要添加一个开关，防止重复请求
                    if (chat.isRefreshing) {
                        chat.get_token()
                    }
                    chat.isRefreshing = false;
                    // 这个Promise函数很关键
                    const retryOriginalRequest = new Promise((resolve) => {
                        chat.addSubscriber(() => {
                            resolve(chat.default_ajax(options, callback))
                        })
                    });
                    return retryOriginalRequest;
                } else if (requestObject.status === 400) {
                    if (res.msg) {
                        alert(res.msg)
                    } else {
                        alert(res)
                    }
                } else {
                    return requestObject;
                }
            }
            $.ajax(options)
        },
        get_ajax: function (url, data, callback) {
            var options = {
                url: chat.host + url,
                data: data,
                type: 'get',
                async: true,
                timeout: 30000,
                cache: false,
                processData: false
            };
            chat.default_ajax(options, callback)
        },
        post_ajax: function (url, data, callback) {
            // console.log(typeof(data))
            // console.log(data instanceof Object)
            if (typeof (data) == "object") {
                data = JSON.stringify(data)
            }
            var options = {
                url: chat.host + url,
                data: data,
                type: 'post',
                datatype: 'json',
                contentType: 'application/json',
                async: true,
                timeout: 30000,
                cache: false,
                processData: false
            }
            chat.default_ajax(options, callback)
        },
        get_token: function () {
            var auth = sessionStorage.getItem("auth", auth);
            $.ajax({
                url: chat.host + "/user/token",
                type: "get",
                headers: { "Authorization": "Basic " + auth },
                success: function (res) {
                    sessionStorage.setItem("token", res.token);
                    sessionStorage.setItem("auth", auth);
                    chat.onAccessTokenFetched();
                    chat.isRefreshing = true;
                },
                fail: function (res) {
                    alert("用户信息失效，请重新登录!");
                    window.location.href = "/";
                }
            })
        },
        check_status: function (response, options, callback) {
            if (response && response.status === 401) {
                // 刷新token的函数,这需要添加一个开关，防止重复请求
                if (chat.isRefreshing) {
                    chat.get_token()
                }
                chat.isRefreshing = false;
                // 这个Promise函数很关键
                const retryOriginalRequest = new Promise((resolve) => {
                    chat.addSubscriber(() => {
                        resolve(chat.default_ajax(options, callback))
                    })
                });
                return retryOriginalRequest;
            } else {
                return response;
            }
        },
        onAccessTokenFetched: function () {
            chat.subscribers.forEach((callback) => {
                callback();
            });
            chat.subscribers = [];
        },
        addSubscriber: function (callback) {
            chat.subscribers.push(callback)
        }
    };
    var listen_back = {
        listen: function (callback) {
            document.addEventListener('plusready', function () {
                var webview = plus.webview.currentWebview();
                plus.key.addEventListener('backbutton', function () {
                    webview.canBack(function (e) {
                        if (e.canBack) {
                            callback();
                            webview.back();
                        } else {
                            webview.close(); //hide,quit
                        }
                    })
                });
            })
        },
        re_back: function (callback) {
            // 监听窗口事件，当窗口关闭时，主动断开websocket连接，防止连接没断开就关闭窗口，server端报错
            window.onbeforeunload = () => {
                callback()
            }
        }
    }
    window.listen_back = listen_back;
    window.chat = chat;
})(this);
