package stores

import (
	"errors"
	"net/http"
	"time"

	"github.com/gorilla/securecookie"
)

type CookieStore struct {
	CookieName  string
	Cookies     []*http.Cookie
	CookieToSet *http.Cookie
	svc         *securecookie.SecureCookie
}

func NewCookieStore(hashKey, blockKey, CookieName string) *CookieStore {
	return &CookieStore{
		CookieName: CookieName,
		svc:        securecookie.New([]byte(hashKey), []byte(blockKey)),
	}
}

func (s *CookieStore) Save(state string, b []byte) error {
	encoded, err := s.svc.Encode(s.CookieName, map[string][]byte{
		state: b,
	})
	if err != nil {
		return err
	}
	cookie := &http.Cookie{
		Name:     s.CookieName,
		Value:    encoded,
		Path:     "/",
		Secure:   true,
		HttpOnly: true,
		Expires:  time.Now().Add(3 * time.Minute),
	}
	s.CookieToSet = cookie

	return nil
}

func (s *CookieStore) Get(state string) ([]byte, error) {
	for _, c := range s.Cookies {
		if c.Name == s.CookieName {
			value := make(map[string][]byte)
			if err := s.svc.Decode(s.CookieName, c.Value, &value); err != nil {
				return nil, errors.New("invalid state cookie value")
			}
			v, ok := value[state]
			if !ok {
				return nil, errors.New("state not found")
			}
			return v, nil
		}
	}
	return nil, errors.New("state not found")
}

func (s *CookieStore) Delete(state string) error {
	for _, c := range s.Cookies {
		if c.Name == s.CookieName {
			s.CookieToSet = c
			s.CookieToSet.Expires = time.Unix(0, 0)
			s.CookieToSet.MaxAge = -1
		}
	}

	return nil
}

var _ GocialStore = &CookieStore{}
