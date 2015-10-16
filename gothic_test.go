package gothic

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/markbates/goth"
)

func init() {
	goth.UseProviders(&mockProvider{})
}

func wr(method, url string, body io.Reader) (*httptest.ResponseRecorder, *http.Request) {
	r, err := http.NewRequest(method, url, body)
	if err != nil {
		panic(err)
	}
	return httptest.NewRecorder(), r
}

func beginAuthCookie() string {
	w, r := wr("GET", "/", nil)
	err := BeginAuth(providerName, w, r)
	if err != nil {
		panic(err)
	}
	sc := w.Header().Get("Set-Cookie")
	return sc[:strings.Index(sc, ";")]
}

func verifyUser(t *testing.T, user goth.User) {
	if user.Provider != providerName {
		t.Errorf("expected user.Provider value %q got %q", providerName, user.Provider)
	}
	if user.AccessToken != userAccessToken {
		t.Errorf("expected user.AccessToken value %q got %q", userAccessToken, user.AccessToken)
	}
	if user.Email != userEmail {
		t.Errorf("expected user.Email value %q got %q", userEmail, user.Email)
	}
	if user.Name != userName {
		t.Errorf("expected user.Name value %q got %q", userName, user.Name)
	}
	if user.NickName != userNickName {
		t.Errorf("expected user.NickName value %q got %q", userNickName, user.NickName)
	}
}

func TestGetAuthURL(t *testing.T) {
	w, r := wr("GET", "/", nil)
	url, err := GetAuthURL(providerName, w, r)
	if err != nil {
		t.Fatal(err)
	}
	if url != authURL {
		t.Errorf("expected value %q got %q", authURL, url)
	}
}

func TestBeginAuth(t *testing.T) {
	w, r := wr("GET", "/", nil)
	err := BeginAuth(providerName, w, r)
	if err != nil {
		t.Fatal(err)
	}
	if w.Code != http.StatusTemporaryRedirect {
		t.Errorf("expected status code %q got %q", http.StatusTemporaryRedirect, w.Code)
	}
	if w.Header().Get("Location") != authURL {
		t.Errorf("expected %q in location header got %q", authURL, w.Header().Get("Location"))
	}
	if w.Header().Get("Set-Cookie") == "" {
		t.Error("expected cookie exists got none")
	}
}

func TestCompleteAuth(t *testing.T) {
	cookie := beginAuthCookie()
	w, r := wr("GET", "/?state="+lastState, nil)
	r.Header.Set("Cookie", cookie)
	user, err := CompleteAuth(providerName, w, r)
	if err != nil {
		t.Fatal(err)
	}
	verifyUser(t, user)
}

func TestCompleteAuthNoCookie(t *testing.T) {
	w, r := wr("GET", "/", nil)
	_, err := CompleteAuth(providerName, w, r)
	if err == nil {
		t.Fatal("expected error got none")
	}
	msg := "http: named cookie not present"
	if err.Error() != msg {
		t.Fatalf("expected %q got %q", msg, err)
	}
}

func TestCompleteAuthBrokenCookie(t *testing.T) {
	w, r := wr("GET", "/", nil)
	r.Header.Set("Cookie", CookieName+"=broken value")
	_, err := CompleteAuth(providerName, w, r)
	if err == nil {
		t.Fatal("expected error got none")
	}
	msg := "securecookie"
	if err.Error()[:len(msg)] != msg {
		t.Fatalf("expected %q error got %q", msg, err)
	}
}

func TestCompleteAuthStateMismatch(t *testing.T) {
	w, r := wr("GET", "/", nil)
	r.Header.Set("Cookie", beginAuthCookie())
	_, err := CompleteAuth(providerName, w, r)
	if err == nil {
		t.Fatal("expected error got none")
	}
	msg := "oauth 2.0 state parameter does not match"
	if err.Error() != msg {
		t.Fatalf("expected %q got %q", msg, err)
	}
}

func TestCompleteAuthSkipStateCheck(t *testing.T) {
	StateUnsupportedProvider[providerName] = struct{}{}
	w, r := wr("GET", "/", nil)
	r.Header.Set("Cookie", beginAuthCookie())
	user, err := CompleteAuth(providerName, w, r)
	if err != nil {
		t.Fatal(err)
	}
	verifyUser(t, user)
	delete(StateUnsupportedProvider, providerName)
}
