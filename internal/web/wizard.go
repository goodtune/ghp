package web

import (
	"encoding/json"
	"net/http"

	"github.com/goodtune/ghp/internal/crypto"
)

const wizardCookieName = "ghp_wizard"

// WizardState holds the accumulated wizard form data across steps.
type WizardState struct {
	Step        int               `json:"step"`
	Repository  string            `json:"repository,omitempty"`
	Permissions map[string]string `json:"permissions,omitempty"`
	Duration    string            `json:"duration,omitempty"`
	SessionID   string            `json:"session_id,omitempty"`
}

func setWizardCookie(w http.ResponseWriter, enc *crypto.Encryptor, state *WizardState) error {
	data, err := json.Marshal(state)
	if err != nil {
		return err
	}
	encrypted, err := enc.Encrypt(string(data))
	if err != nil {
		return err
	}
	http.SetCookie(w, &http.Cookie{
		Name:     wizardCookieName,
		Value:    encrypted,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
	return nil
}

func getWizardCookie(r *http.Request, enc *crypto.Encryptor) (*WizardState, error) {
	cookie, err := r.Cookie(wizardCookieName)
	if err != nil {
		return &WizardState{Step: 1}, nil // No cookie = fresh wizard
	}
	decrypted, err := enc.Decrypt(cookie.Value)
	if err != nil {
		return &WizardState{Step: 1}, nil // Corrupt cookie = start over
	}
	var state WizardState
	if err := json.Unmarshal([]byte(decrypted), &state); err != nil {
		return &WizardState{Step: 1}, nil
	}
	return &state, nil
}

func clearWizardCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:   wizardCookieName,
		Value:  "",
		Path:   "/dashboard/token/add/",
		MaxAge: -1,
	})
}
