package indieauth

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/sessions"
	"golang.org/x/net/publicsuffix"
)

func TestServer(t *testing.T) {
	cookies := sessions.NewCookieStore([]byte("my-secret"))

	// Mock the indieauth server
	iaMux := http.NewServeMux()
	iaMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		t.Logf("mock /")
		w.Write([]byte(fmt.Sprintf(`<!doctype html><html><head><meta charset=utf-8><link rel="authorization_endpoint" href="/indieauth"></head></html>`)))

	})
	iaMux.HandleFunc("/indieauth", func(w http.ResponseWriter, r *http.Request) {
		t.Logf("mock /indieauth")
		if r.Method == "GET" {
			http.Redirect(w, r, r.URL.Query().Get("redirect_uri")+"?code=ok&state="+r.URL.Query().Get("state")+"&me="+r.URL.Query().Get("me"), http.StatusTemporaryRedirect)
			return
		}
		t.Logf("mock POST /indieauth")
		w.Header().Set("Content-Type", "application/json")
		// FIXME(tsileo): vary this and return 403
		w.Write([]byte(`{}`))
	})
	iaServer := httptest.NewServer(iaMux)
	t.Logf("indieauth mock server: %s", iaServer.URL)

	// Create a server that use the lib
	s, err := New(cookies, iaServer.URL, "")
	if err != nil {
		panic(err)
	}
	m := s.Middleware()

	mux := http.NewServeMux()
	mux.HandleFunc("/indieauth-redirect", s.RedirectHandler)
	mux.Handle("/", m(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Logf("hello")
		w.Write([]byte("hello"))
	})))

	server := httptest.NewServer(mux)
	s.clientID = server.URL
	s.redirectURI = server.URL + "/indieauth-redirect"

	// Setup a client with cookies support
	jar, err := cookiejar.New(&cookiejar.Options{PublicSuffixList: publicsuffix.List})
	if err != nil {
		log.Fatal(err)
	}

	client := &http.Client{
		Jar: jar,
	}
	resp, err := client.Get(server.URL)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Errorf("expected 200, got %d", resp.StatusCode)
	}
	data, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		panic(err)
	}
	if string(data) != "hello" {
		t.Errorf("bad response, expected \"hello\", got \"%s\"", data)
	}
}
