
# Авторизация nginx auth_request
nginx.conf
```
server {
    server_name <domain>;
    listen <port>;
    index index.html;
    
#    auth_request /auth;

    location /secret {
        alias <path>;
        auth_request /auth;
#       получаем и устанавливаем кукисы в браузере        
        auth_request_set $saved_set_cookie $upstream_http_set_cookie;
        add_header Set-Cookie $saved_set_cookie;
        
        auth_request_set $auth_status $upstream_status;

#       получаем адрес редиректа и если он есть редиректим
        auth_request_set $redirect_uri $sent_http_x_redirect;
        if ($redirect_uri != "") {
            return 302 $scheme://$host$redirect_uri;
        }

    }

    location /auth {
        proxy_pass http://localhost:8880;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
#       токен для валидации login button
        proxy_set_header X-Token "<token>"";
        proxy_set_header X-URI $request_uri;
#       название проекта. Необходим для валидации кукисов
        proxy_set_header X-Project "7keys-dev";
        proxy_set_header Host $host;
    }
}
```

.env
```sh
RDB_URL=redis://localhost:6379/15
HOST=localhost:8880
```