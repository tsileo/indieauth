# IndieAuth

[![Build Status](https://travis-ci.org/tsileo/indieauth.svg?branch=master)](https://travis-ci.org/tsileo/indieauth)
&nbsp; &nbsp;[![Godoc Reference](https://godoc.org/a4.io/indieauth?status.svg)](https://godoc.org/a4.io/indieauth)

This package is designed to replace basic authentication by [IndieAuth](https://www.w3.org/TR/indieauth/) in personal projects 
when you want to restrict access only to yourself.

It's not designed to handle multiple users.

## QuickStart

```bash
$ get get a4.io/indieauth
```

```go
package main

import (
        "log"
        "net/http"

        "a4.io/indieauth"
        "github.com/gorilla/sessions"
)

var cookieStore = sessions.NewCookieStore([]byte("my-secret"))

func main() {
        indie, err := indieauth.New(cookieStore, "https://my.indie.auth.domain", "https://my.app.id")
        if err != nil {
                panic(err)
        }
        authMiddleware := indie.Middleware()
        http.HandleFunc("/indieauth-redirect", indie.RedirectHandler)
        http.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
                indie.Logout(w, r)
        })
        http.Handle("/", authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
                w.Write([]byte("YAY!"))
        })))
        log.Fatal(http.ListenAndServe(":8011", nil))
}
```
