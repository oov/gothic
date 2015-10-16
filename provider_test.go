package gothic

import (
	"encoding/json"
	"strings"

	"github.com/markbates/goth"
)

const (
	providerName    = "mock"
	authURL         = "http://example.com/auth/"
	userAccessToken = "mokken"
	userEmail       = "mocker@example.com"
	userName        = "mock'n'role"
	userNickName    = "mocker"
)

var lastState string

type mockProvider struct{}

func (p *mockProvider) Name() string {
	return providerName
}

func (p *mockProvider) BeginAuth(state string) (goth.Session, error) {
	lastState = state
	return &mockSession{Email: userEmail, Name: userName, NickName: userNickName, AccessToken: userAccessToken}, nil
}

func (p *mockProvider) UnmarshalSession(data string) (goth.Session, error) {
	s := &mockSession{}
	return s, json.NewDecoder(strings.NewReader(data)).Decode(s)
}

func (p *mockProvider) FetchUser(s goth.Session) (goth.User, error) {
	ms := s.(*mockSession)
	return goth.User{Provider: p.Name(), Email: ms.Email, Name: ms.Name, NickName: ms.NickName, AccessToken: ms.AccessToken}, nil
}

func (p *mockProvider) Debug(debug bool) {}

type mockSession struct {
	AccessToken string
	Email       string
	Name        string
	NickName    string
}

func (s *mockSession) GetAuthURL() (string, error) {
	return authURL, nil
}

func (s *mockSession) Marshal() string {
	b, _ := json.Marshal(s)
	return string(b)
}

func (s *mockSession) Authorize(pr goth.Provider, ps goth.Params) (string, error) {
	return s.AccessToken, nil
}
