# go-session-redis
Simple HTTP session management

## Example middleware (Chi router)
```go
func SessionAuthenticator(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, err := session.SessionManager.GetOrCreateSession(w, r)
		if err != nil {
			http.Error(w, err.Error(), http.StatusUnauthorized)
			return
		}

		id := s.Get("id")
		if id == "" || id == nil {
			http.Error(w, "Not authenticated", http.StatusUnauthorized)
			return
		}

		err = s.UpdateTTL()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}

		// Session is valid
		next.ServeHTTP(w, r)
	})
}

```
