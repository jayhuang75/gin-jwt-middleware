# gin-jwt-middleware
[![Build Status](https://travis-ci.org/jayhuang75/gin-jwt-middleware.svg?branch=master)](https://travis-ci.org/jayhuang75/gin-jwt-middleware)

## What is JWT?
JSON Web Token (JWT) more information: 
[http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html](http://self-issued.info/docs/draft-ietf-oauth-json-web-token.html)

## How to use this?
#### Install package
```bash
$ go get github.com/jayhuang75/gin-jwt-middleware
```

#### In your gin application main.go, import the package
```go
import (
    "github.com/jayhuang75/gin-jwt-middleware"
)
```

#### Use the middleware
```go
app := gin.Default()

app.Use(auth.JWTAuthMiddleware(encoded, YOUR_SECRET)
```

- encoded is a boolen: if your JWT secret is encoded
- YOUR_SECRET: Your JWT secret, here you can use the env variable
