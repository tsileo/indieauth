/*
Package indieauth implements an IndieAuth (an identity layer on top of OAuth 2.0)] client/authentication middleware.
*/
package indieauth // import "a4.io/go/indieauth"

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/gorilla/sessions"
	"github.com/hashicorp/golang-lru"
	"willnorris.com/go/microformats"
)

const (
	ua          = "IndieAuth client (+https://a4.io/go/indieauth)"
	sessionName = "indieauth"
)

// ErrForbidden is returned when the authorization endpoint answered a 403
var ErrForbidden = errors.New("authorization endpoint answered with forbidden")

// IndieAuth holds the auth manager
type IndieAuth struct {
	me           string
	authEndpoint string
	store        *sessions.CookieStore
	cache        *lru.Cache
	clientID     string
	redirectURI  string
}

// New initializes a indieauth auth manager
func New(store *sessions.CookieStore, me, clientID string) (*IndieAuth, error) {
	c, err := lru.New(64)
	if err != nil {
		return nil, err
	}
	authEndpoint, err := getAuthEndpoint(me)
	if err != nil {
		return nil, fmt.Errorf("failed to get \"authorization_endpoint\": %v", err)
	}
	ia := &IndieAuth{
		me:           me,
		clientID:     clientID,
		redirectURI:  clientID + "/indieauth-redirect",
		authEndpoint: authEndpoint,
		store:        store,
		cache:        c,
	}
	return ia, nil
}

// getAuthEndpoint calls the "me" URL with a microformats2 parser to fetch the "authorization_endpoint"
func getAuthEndpoint(me string) (string, error) {
	req, err := http.NewRequest("GET", me, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("User-Agent", ua)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", nil
	}
	defer resp.Body.Close()
	data := microformats.Parse(resp.Body, resp.Request.URL)
	authEndpoints := data.Rels["authorization_endpoint"]
	if len(authEndpoints) == 0 {
		return "", fmt.Errorf("no authorization_endpoint")
	}
	return authEndpoints[0], nil
}

type verifyResp struct {
	Me    string `json:"me"`
	State string `json:"state"`
	Scope string `json:"scope"`
}

// verifyCode calls the authorization endpoint to verify/authenticate the received code
func (ia *IndieAuth) verifyCode(code string) (*verifyResp, error) {
	vs := &url.Values{}
	vs.Set("code", code)
	vs.Set("client_id", ia.clientID)
	vs.Set("redirect_uri", ia.redirectURI)

	req, err := http.NewRequest("POST", ia.authEndpoint, strings.NewReader(vs.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusForbidden {
		return nil, ErrForbidden
	}
	if resp.StatusCode != http.StatusOK {
		return nil, err
	}
	vresp := &verifyResp{}
	if err := json.NewDecoder(resp.Body).Decode(vresp); err != nil {
		panic(err)
	}
	return vresp, nil
}

// RedirectHandler is a HTTP handler that must be registered on the app at `/indieauth-redirect`
func (ia *IndieAuth) RedirectHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		q := r.URL.Query()
		me := q.Get("me")
		code := q.Get("code")
		state := q.Get("state")

		if me != ia.me {
			panic("invalid me")
		}

		p, validState := ia.cache.Get(state)
		if !validState {
			panic(fmt.Errorf("invalid state"))
		}

		if _, err := ia.verifyCode(code); err != nil {
			if err == ErrForbidden {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			panic(err)
		}
		session, _ := ia.store.Get(r, sessionName)
		session.Values["logged_in"] = true
		session.Save(r, w)
		http.Redirect(w, r, p.(string), http.StatusTemporaryRedirect)

	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
	}
}

// Redirect responds to the request by redirecting to the authorization endpoint
func (ia *IndieAuth) Redirect(w http.ResponseWriter, r *http.Request) error {
	pu, err := url.Parse(ia.authEndpoint)
	if err != nil {
		return err
	}

	// Generate a random state
	rawState := make([]byte, 12)
	if _, err := rand.Read(rawState); err != nil {
		return err
	}
	state := fmt.Sprintf("%x", rawState)

	// Store the state in the LRU cache
	ia.cache.Add(state, r.URL.String())

	// Add the query params
	q := pu.Query()
	q.Set("me", ia.me)
	q.Set("client_id", ia.clientID)
	q.Set("redirect_uri", ia.redirectURI)
	q.Set("state", state)
	pu.RawQuery = q.Encode()

	// Do the redirect
	http.Redirect(w, r, pu.String(), http.StatusTemporaryRedirect)
	return nil
}

// Check returns true if there is an existing session with a valid login
func (ia *IndieAuth) Check(r *http.Request) bool {
	// Check if there's a session and if the the user is already logged in
	session, _ := ia.store.Get(r, sessionName)
	loggedIn, ok := session.Values["logged_in"]
	return ok && loggedIn.(bool)
}

// Middleware provides a middleware that will only only user authenticated against with the indieauth endpoint
func (ia *IndieAuth) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.String() != "/indieauth-redirect" && !ia.Check(r) {
				if err := ia.Redirect(w, r); err != nil {
					if err == ErrForbidden {
						w.WriteHeader(http.StatusForbidden)
						return
					}
					panic(err)
				}
				return
			}

			// The user is already logged in
			next.ServeHTTP(w, r)
			return
		})
	}
}

// Logout logs out the current user
func (ia *IndieAuth) Logout(w http.ResponseWriter, r *http.Request) {
	session, _ := ia.store.Get(r, "indieauth")
	session.Values["logged_in"] = false
	session.Save(r, w)
}
