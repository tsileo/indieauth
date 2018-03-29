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

type mockIndieAuthServer struct {
	Code  string
	State string
	Me    string

	indexCall, authCall, verifCall int

	t *testing.T
	s *httptest.Server
}

func (s *mockIndieAuthServer) IndexHandler(w http.ResponseWriter, r *http.Request) {
	s.indexCall++
	s.t.Logf("MockIndieAuthServer GET /")
	w.Write([]byte(fmt.Sprintf(`<!doctype html><html><head><meta charset=utf-8><link rel="authorization_endpoint" href="/indieauth"></head></html>`)))
}

func (s *mockIndieAuthServer) AuthHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		s.authCall++
		s.t.Logf("MockIndieAuthServer GET /indieauth")
		http.Redirect(w, r, r.URL.Query().Get("redirect_uri")+"?code="+s.Code+"&state="+r.URL.Query().Get("state")+"&me="+r.URL.Query().Get("me"), http.StatusTemporaryRedirect)
	case "POST":
		s.verifCall++
		s.t.Logf("MockIndieAuthServer POST /indieauth")
		w.Header().Set("Content-Type", "application/json")
		// FIXME(tsileo): vary this and return 403
		w.Write([]byte("{\"me\":\"" + s.Me + "\"}"))
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

func newMockIndieAuthServer(t *testing.T) *mockIndieAuthServer {
	// Mock the indieauth server
	iaMux := http.NewServeMux()
	mockServer := &mockIndieAuthServer{Code: "lol", t: t}
	iaMux.HandleFunc("/", mockServer.IndexHandler)
	iaMux.HandleFunc("/indieauth", mockServer.AuthHandler)
	iaServer := httptest.NewServer(iaMux)
	mockServer.s = iaServer
	mockServer.Me = iaServer.URL
	return mockServer
}

func TestAuthorizationEndpointDiscoveryLinkTag(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(fmt.Sprintf(`<!doctype html><html><head><meta charset=utf-8><link rel="authorization_endpoint" href="/indieauth"></head></html>`)))
	})
	server := httptest.NewServer(mux)

	authEndpoint, err := getAuthEndpoint(server.URL)
	if err != nil {
		panic(err)
	}

	if authEndpoint != server.URL+"/indieauth" {
		t.Errorf("failed to discover authorization endpoint, expected \"%s/indieauth\", got %q", server.URL, authEndpoint)
	}
}

func TestAuthorizationEndpointDiscoveryLinkHeader(t *testing.T) {
	mux := http.NewServeMux()
	var serverURL string
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Link", fmt.Sprintf("<%s/indieauth>; rel=\"authorization_endpoint\"", serverURL))
	})
	server := httptest.NewServer(mux)
	serverURL = server.URL

	authEndpoint, err := getAuthEndpoint(server.URL)
	if err != nil {
		panic(err)
	}

	if authEndpoint != serverURL+"/indieauth" {
		t.Errorf("failed to discover authorization endpoint, expected \"%s/indieauth\", got %q", serverURL, authEndpoint)
	}
}

func TestAuthorizationEndpointDiscovery(t *testing.T) {
	mux := http.NewServeMux()
	var serverURL string
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// From the spec (https://www.w3.org/TR/indieauth/#x4-1-discovery-by-clients):
		// >>> the first HTTP Link header takes precedence, followed by the first <link> element in document order.
		// The client should discover `serverURL + "/lol"`
		w.Header().Set("Link", fmt.Sprintf("<%s/lol>; rel=\"authorization_endpoint\"", serverURL))
		w.Write([]byte(fmt.Sprintf(`<!doctype html><html><head><meta charset=utf-8><link rel="authorization_endpoint" href="/indieauth"></head></html>`)))
	})
	server := httptest.NewServer(mux)
	serverURL = server.URL

	authEndpoint, err := getAuthEndpoint(server.URL)
	if err != nil {
		panic(err)
	}

	if authEndpoint != serverURL+"/lol" {
		t.Errorf("failed to discover authorization endpoint, expected \"%s/lol\", got %q", serverURL, authEndpoint)
	}

}

func TestMiddleware(t *testing.T) {
	cookies := sessions.NewCookieStore([]byte("my-secret"))

	mockServer := newMockIndieAuthServer(t)

	// Create a server that use the lib
	s, err := New(cookies, mockServer.Me)
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
	if mockServer.authCall != 1 {
		t.Errorf("the authorization endpoint wasn't called")
	}
	if mockServer.verifCall != 1 {
		t.Errorf("code was not verified")
	}
}
