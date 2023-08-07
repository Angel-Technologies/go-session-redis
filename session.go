package session

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/redis/go-redis/v9"
)

var RDb = redis.NewClient(&redis.Options{
	Addr:     "localhost:6379",
	Password: "123",
	DB:       0, // use default DB
})

var expires = int(96 * time.Hour)
var SessionManager = InitSession("sid", expires)

type SessionInterface interface {
	Write() (error, bool)
	UpdateTTL() error
	Read() (error, bool)
	Set(key string, value interface{})
	Get(key string) interface{}
	ID() string
	Delete(string)
	Destroy() error
}

type Manager struct {
	privateCookieName string
	lock              sync.Mutex
	maxLifeTTL        time.Duration
}

func InitSession(cookieName string, ttl int) *Manager {
	return &Manager{
		privateCookieName: cookieName,
		lock:              sync.Mutex{},
		maxLifeTTL:        time.Duration(ttl),
	}
}

type Session struct {
	sid     string
	Storage *SessionStorage
	ttl     time.Duration
}

type SessionStorage struct {
	Values map[string]interface{}
}

func (m *Manager) createSession() (*Session, *http.Cookie) {
	v := make(map[string]interface{}, 0)
	session := &Session{
		sid:     m.sessionID(),
		Storage: &SessionStorage{Values: v},
		ttl:     m.maxLifeTTL,
	}
	session.Write()

	cookie := &http.Cookie{
		Name:     m.privateCookieName,
		Value:    url.QueryEscape(session.sid),
		Path:     "/",
		HttpOnly: true,
		MaxAge:   int(m.maxLifeTTL / time.Second),
	}

	return session, cookie
}

func (m *Manager) GetOrCreateSession(w http.ResponseWriter, r *http.Request) (SessionInterface, error) {
	m.lock.Lock()
	defer m.lock.Unlock()

	cookie, err := r.Cookie(m.privateCookieName)
	if err != nil || cookie.Value == "" {
		session, cookie := m.createSession()
		http.SetCookie(w, cookie)
		return session, nil
	} else {
		sid, _ := url.QueryUnescape(cookie.Value)
		session := &Session{sid: sid}
		if _, ok := session.Read(); ok {
			return session, nil
		} else {
			session, cookie := m.createSession()
			http.SetCookie(w, cookie)
			return session, nil
		}

	}
}

func (m *Manager) sessionID() string {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return ""
	}

	return base64.URLEncoding.EncodeToString(b)
}

func (sm *Session) Read() (error, bool) {
	val, err := RDb.Get(context.Background(), sm.sid).Result()
	if err == redis.Nil {
		return err, false
	}

	st := &SessionStorage{}
	err = json.Unmarshal([]byte(val), st)
	if err != nil {
		return err, false
	}

	sm.Storage = st

	ttl, err := RDb.TTL(context.Background(), sm.sid).Result()
	if err != nil {
		return err, false
	}

	sm.ttl = ttl

	return nil, true
}

func (sm *Session) Write() (error, bool) {
	val, err := json.Marshal(sm.Storage)
	if err != nil {
		return err, false
	}

	err = RDb.Set(context.Background(), sm.sid, val, sm.ttl).Err()
	if err != nil {
		return err, false
	}

	return nil, true
}

func (sm *Session) UpdateTTL() error {
	return RDb.Expire(context.Background(), sm.sid, time.Duration(expires)).Err()
}

func (sm *Session) Get(key string) interface{} {
	if val, ok := sm.Storage.Values[key]; ok {
		return val
	} else {
		return nil
	}
}

func (sm *Session) ID() string {
	return sm.sid
}

func (sm *Session) Set(key string, value interface{}) {
	sm.Storage.Values[key] = value
}

func (sm *Session) Delete(key string) {
	delete(sm.Storage.Values, key)
}

func (sm *Session) Destroy() error {
	sm.sid = ""
	sm.Storage = &SessionStorage{}
	return RDb.Del(context.Background(), sm.sid).Err()
}
