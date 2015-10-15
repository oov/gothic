package gothic

// this code is based on https://github.com/markbates/goth/blob/master/gothic/gothic.go

import (
	"encoding/base64"
	"errors"
	"net/http"
	"os"
	"time"

	"github.com/gorilla/securecookie"
	"github.com/markbates/goth"
)

// Options stores configuration for a secure cookie.
//
// Fields are a subset of http.Cookie fields.
type Options struct {
	Path   string
	Domain string
	// MaxAge=0 means no 'Max-Age' attribute specified.
	// MaxAge<0 means delete cookie now, equivalently 'Max-Age: 0'.
	// MaxAge>0 means Max-Age attribute present and given in seconds.
	MaxAge   int
	Secure   bool
	HttpOnly bool
}

// CookieName is the key used to access the secure cookie.
var CookieName = "_gothic"

// CookieOptions is the options used to access the secure cookie.
var CookieOptions = Options{
	Path: "/",
}

// StateUnsupportedProvider is the list of OAuth2.0 state parameter unsupported provider.
var StateUnsupportedProvider = map[string]struct{}{
	"twitter": struct{}{},
	"lastfm":  struct{}{},
}

var codecs []securecookie.Codec

const stateLen = 16

func init() {
	a := []byte(os.Getenv("GOTHIC_COOKIE_AUTH"))
	if len(a) == 0 {
		a = securecookie.GenerateRandomKey(64)
	}

	e := []byte(os.Getenv("GOTHIC_COOKIE_ENCRYPT"))
	if len(e) == 0 {
		codecs = securecookie.CodecsFromPairs(a)
	} else {
		codecs = securecookie.CodecsFromPairs(a, e)
	}
}

// BeginAuth is a convienence function for starting the authentication process.
//
// BeginAuth will redirect the user to the appropriate authentication end-point
// for the requested provider.
func BeginAuth(providerName string, w http.ResponseWriter, r *http.Request) error {
	url, err := GetAuthURL(providerName, w, r)
	if err != nil {
		return err
	}

	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
	return nil
}

// GetAuthURL starts the authentication process with the requested provided.
// It will return a URL that should be used to send users to.
//
// I would recommend using the BeginAuth instead of doing all of these steps
// yourself.
func GetAuthURL(providerName string, w http.ResponseWriter, r *http.Request) (string, error) {
	provider, err := goth.GetProvider(providerName)
	if err != nil {
		return "", err
	}

	state := base64.URLEncoding.EncodeToString(securecookie.GenerateRandomKey(stateLen * 3 / 4))
	sess, err := provider.BeginAuth(state)
	if err != nil {
		return "", err
	}

	url, err := sess.GetAuthURL()
	if err != nil {
		return "", err
	}

	encoded, err := securecookie.EncodeMulti(CookieName, state+sess.Marshal(), codecs...)
	if err != nil {
		return "", err
	}

	http.SetCookie(w, cookie(CookieName, encoded, &CookieOptions))

	return url, err
}

// CompleteUserAuth completes the authentication process and fetches all of the
// basic information about the user from the provider.
func CompleteUserAuth(providerName string, w http.ResponseWriter, r *http.Request) (goth.User, error) {
	provider, err := goth.GetProvider(providerName)
	if err != nil {
		return goth.User{}, err
	}

	c, err := r.Cookie(CookieName)
	if err != nil {
		return goth.User{}, err
	}

	if c.Value == "" {
		return goth.User{}, errors.New("could not find a matching session for this request")
	}

	var ss string
	err = securecookie.DecodeMulti(CookieName, c.Value, &ss, codecs...)
	if err != nil {
		return goth.User{}, err
	}

	co := CookieOptions
	co.MaxAge = -1
	http.SetCookie(w, cookie(CookieName, "", &co))

	// verify state
	_, stateUnsupported := StateUnsupportedProvider[providerName]
	if len(ss) < stateLen || (!stateUnsupported && r.URL.Query().Get("state") != ss[:stateLen]) {
		return goth.User{}, errors.New("could not find a matching session for this request")
	}

	sess, err := provider.UnmarshalSession(ss[stateLen:])
	if err != nil {
		return goth.User{}, err
	}

	_, err = sess.Authorize(provider, r.URL.Query())
	if err != nil {
		return goth.User{}, err
	}

	return provider.FetchUser(sess)
}

func cookie(name, value string, opt *Options) *http.Cookie {
	c := http.Cookie{
		Name:     name,
		Value:    value,
		Path:     opt.Path,
		Domain:   opt.Domain,
		MaxAge:   opt.MaxAge,
		Secure:   opt.Secure,
		HttpOnly: opt.HttpOnly,
	}
	switch {
	case c.MaxAge < 0:
		c.Expires = time.Unix(1, 0)
	case c.MaxAge > 0:
		c.Expires = time.Now().Add(time.Duration(c.MaxAge) * time.Second)
	}
	return &c
}
