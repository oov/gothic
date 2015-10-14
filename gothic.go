package gothic

// this code is based on https://github.com/markbates/goth/blob/master/gothic/gothic.go

import (
	"encoding/gob"
	"errors"
	"net/http"
	"os"

	"github.com/gorilla/sessions"
	"github.com/markbates/goth"
)

// SessionName is the key used to access the session store.
const SessionName = "_gothic"

// Store can/should be set by applications using gothic. The default is a cookie store.
var Store = sessions.NewCookieStore([]byte(os.Getenv("SESSION_SECRET")))

type key int

const sessionKey key = 0

func init() {
	gob.Register(sessionKey)
}

/*
BeginAuthHandler is a convienence handler for starting the authentication process.
It expects to be able to get the name of the provider from the query parameters
as either "provider" or ":provider".

BeginAuthHandler will redirect the user to the appropriate authentication end-point
for the requested provider.

See https://github.com/markbates/goth/examples/main.go to see this in action.
*/
func BeginAuthHandler(providerName string, w http.ResponseWriter, r *http.Request) {
	url, err := GetAuthURL(providerName, w, r)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	http.Redirect(w, r, url, http.StatusTemporaryRedirect)
}

// GetState gets the state string associated with the given request
// This state is sent to the provider and can be retrieved during the
// callback.
var GetState = func(req *http.Request) string {
	return req.URL.Query().Get("state")
}

/*
GetAuthURL starts the authentication process with the requested provided.
It will return a URL that should be used to send users to.

I would recommend using the BeginAuthHandler instead of doing all of these steps
yourself, but that's entirely up to you.
*/
func GetAuthURL(providerName string, w http.ResponseWriter, r *http.Request) (string, error) {
	provider, err := goth.GetProvider(providerName)
	if err != nil {
		return "", err
	}

	sess, err := provider.BeginAuth(GetState(r))
	if err != nil {
		return "", err
	}

	url, err := sess.GetAuthURL()
	if err != nil {
		return "", err
	}

	session, _ := Store.Get(r, SessionName)
	session.Values[sessionKey] = sess.Marshal()
	err = session.Save(r, w)
	if err != nil {
		return "", err
	}

	return url, err
}

/*
CompleteUserAuth does what it says on the tin. It completes the authentication
process and fetches all of the basic information about the user from the provider.

See https://github.com/markbates/goth/examples/main.go to see this in action.
*/
var CompleteUserAuth = func(providerName string, w http.ResponseWriter, r *http.Request) (goth.User, error) {
	provider, err := goth.GetProvider(providerName)
	if err != nil {
		return goth.User{}, err
	}

	session, _ := Store.Get(r, SessionName)

	if session.Values[sessionKey] == nil {
		return goth.User{}, errors.New("could not find a matching session for this request")
	}

	sess, err := provider.UnmarshalSession(session.Values[sessionKey].(string))
	if err != nil {
		return goth.User{}, err
	}

	_, err = sess.Authorize(provider, r.URL.Query())
	if err != nil {
		return goth.User{}, err
	}

	delete(session.Values, sessionKey)
	err = session.Save(r, w)
	if err != nil {
		return goth.User{}, err
	}

	return provider.FetchUser(sess)
}
