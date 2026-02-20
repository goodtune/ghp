package github

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAppTokenProvider_GetInstallationToken(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/app/installations/123/access_tokens" && r.Method == "POST" {
			auth := r.Header.Get("Authorization")
			if auth == "" {
				t.Error("expected Authorization header")
			}
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"token":      "ghs_testinstallationtoken",
				"expires_at": time.Now().Add(1 * time.Hour).Format(time.RFC3339),
			})
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer server.Close()

	provider, err := NewAppTokenProvider(AppConfig{
		AppID:      1,
		PrivateKey: testRSAKey,
		BaseURL:    server.URL,
	})
	if err != nil {
		t.Fatal(err)
	}

	token, err := provider.GetInstallationToken(context.Background(), 123, []string{"org/repo"}, map[string]string{"contents": "read"})
	if err != nil {
		t.Fatal(err)
	}
	if token != "ghs_testinstallationtoken" {
		t.Errorf("expected ghs_testinstallationtoken, got %q", token)
	}
}

func TestAppTokenProvider_CachesToken(t *testing.T) {
	callCount := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		callCount++
		w.WriteHeader(http.StatusCreated)
		json.NewEncoder(w).Encode(map[string]interface{}{
			"token":      "ghs_cached",
			"expires_at": time.Now().Add(1 * time.Hour).Format(time.RFC3339),
		})
	}))
	defer server.Close()

	provider, err := NewAppTokenProvider(AppConfig{
		AppID:      1,
		PrivateKey: testRSAKey,
		BaseURL:    server.URL,
	})
	if err != nil {
		t.Fatal(err)
	}

	ctx := context.Background()
	_, _ = provider.GetInstallationToken(ctx, 456, []string{"org/repo"}, map[string]string{"contents": "read"})
	_, _ = provider.GetInstallationToken(ctx, 456, []string{"org/repo"}, map[string]string{"contents": "read"})

	if callCount != 1 {
		t.Errorf("expected 1 API call (cached), got %d", callCount)
	}
}

func TestAppTokenProvider_422ReturnsInstallationTokenError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/app/installations/789/access_tokens":
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusUnprocessableEntity)
			json.NewEncoder(w).Encode(map[string]interface{}{
				"message": "Resource not accessible by integration",
			})
		case "/app/installations/789":
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]interface{}{
				"permissions": map[string]string{
					"contents": "read",
					"metadata": "read",
				},
			})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	provider, err := NewAppTokenProvider(AppConfig{
		AppID:      1,
		PrivateKey: testRSAKey,
		BaseURL:    server.URL,
	})
	if err != nil {
		t.Fatal(err)
	}

	requested := map[string]string{
		"contents": "write",
		"issues":   "read",
	}
	_, err = provider.GetInstallationToken(context.Background(), 789, []string{"org/repo"}, requested)
	if err == nil {
		t.Fatal("expected error, got nil")
	}

	var ite *InstallationTokenError
	if !errors.As(err, &ite) {
		t.Fatalf("expected *InstallationTokenError, got %T: %v", err, err)
	}

	if ite.StatusCode != http.StatusUnprocessableEntity {
		t.Errorf("expected status 422, got %d", ite.StatusCode)
	}

	if ite.Message != "Resource not accessible by integration" {
		t.Errorf("unexpected message: %q", ite.Message)
	}

	missing := ite.MissingPermissions()
	if _, ok := missing["contents"]; !ok {
		t.Errorf("expected contents in missing permissions, got %v", missing)
	}
	if _, ok := missing["issues"]; !ok {
		t.Errorf("expected issues in missing permissions, got %v", missing)
	}
	if _, ok := missing["metadata"]; ok {
		t.Errorf("metadata should not be missing, got %v", missing)
	}
}

func TestInstallationTokenError_MissingPermissions(t *testing.T) {
	ite := &InstallationTokenError{
		StatusCode: 422,
		Message:    "test",
		RequestedPermissions: map[string]string{
			"contents": "write",
			"issues":   "read",
			"metadata": "read",
		},
		GrantedPermissions: map[string]string{
			"contents": "read",
			"metadata": "read",
		},
	}

	missing := ite.MissingPermissions()
	if len(missing) != 2 {
		t.Fatalf("expected 2 missing permissions, got %d: %v", len(missing), missing)
	}
	if missing["contents"] != "write" {
		t.Errorf("expected contents:write missing, got %v", missing)
	}
	if missing["issues"] != "read" {
		t.Errorf("expected issues:read missing, got %v", missing)
	}
}

// testRSAKey is a test-only RSA private key in PEM format.
var testRSAKey = `-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEAwUAwCT0ycvVRxvwAUe4RYLbAyPk2uEEpUJIb0VNvi9WWjPVl
AfRUGuvgnDSs46BbE+cnYSSG36xMDedASH2oH+p/mJb5vSgLpFjIkv/uX8XOmtZ6
jxOX5O12WtNgU2qpCX19UnDYipjY6YylePJ64eKP9XBGMOlGPHCXmFdDY6O+0uPw
wAd211IwT5PkhN/PixGiYpKAn7LvZ3je4Y1cmxRKw0A0CyTVKvG27PlA2jo+pTeK
St8cDa5L4vA6vkFqPqrFrAKa0te33Cu0Kkz6n3tx2DTeI+4pKQid+ze+125crynq
pvu5FMAkXCmVOLCaeHFMg2R+1qXQNoQ2v7QHdQIDAQABAoIBAE8KBjuZJIuhK4/T
nPvlf4ULaiEo0MkemZvDDo6YbgyG0LsZWPUqLcYPCIBLCRVWjjm/NruEGYfdLAQZ
u5CKmFtpaUOLKFzFxrEywOJiu+e++ygYJetj66Gtv9UZFBI6EyX3Be1UizRwnHM1
W65ymnDN3exYPdUea+QndtFPi5fx+JQGrVRzHDCzwBPvqMAebR+OaZ7p3OIAqlOI
Y+RWs/I3DQFXwdRpU1cSTv18/EEcbyOJN4fJv/jk77ntqkOW2tPoZlgOMvdZPqQC
K0DTZDKmfkZGUHwxaQtPR1jnxcx4rWVEFk2dxP5RBs8zUy8BrMwGVW3A5GfB3d2N
m6FNchcCgYEA4H3boVNV37ifGIZM00LV5F51tzRC4plDgnjznp5AZk/H9bJfC/I4
k+EN4VeGjg4jgfTQyEMHBXY6bpTnth7Xh7Yr44Qyji/j5JQFdAVA2ydFc5G95/Zk
LEhqnsnZ96qSQG8jKGrq5TmZumb13I2t22K+pYPbwl8MXgktB1Ck8ucCgYEA3F/S
fmmZkbJreYyubC/ZDidTxEcuVw0GVPtK2/ITi7R+YVqVg5JczBzlQIKGEJabtUrZ
0scS45b/87iw50mzRw0VvitNk/MQ4OJhMdBk1+RWK4m1udY/SQXEHKegO/LSIZbm
LkxR+eZywXVk50lJAyeuMolybxdej3XKvJaaQ0MCgYEAo6AYrYWoWeCfVajN5k4Y
yNNwyY/2EGPVqQuvxjViizArdxID5Rkv09l93HmHQZNcniRq6Qyx2XFLNb6jBUOF
pQ1LABIjJzAQ01JwhxgtJY+CN7JK0P/uE7jUvdgyXyqcXwqifZswitNpEUxqd89s
oTNf8hQh4ZKV2RSnFWXaVJECgYBVIJ7LPjeYVHe3yGRIXmNWWFK/a0+3SMy9XyUX
uXdbbCm1qaw/2vYF0tOsC7+GAOe9LGDgTw445EeS+jE75vhd5ewUPd4F3MsUU95/
w6Rw0T+IKfYNB3oC1zteZlI7Vh1d5FCeadTw19hUaujDf0e49EcSNo4B4+EfQb1D
BFoqyQKBgAJC8ejath862GxPQB9mpkuxwYR+Odp/Uz46xfyrSJrKb0BQrn9v6Kyd
lEYYwchE0C7L13qVoxEJN9U5XtgNERUpCQi3NCHwD8ADwpyAzQP57UBLS8Bb5ByC
xARUAV0AcnOf8WgFfswT1z7K4sJABdSBhP1URlo9YBW41+FAzQbm
-----END RSA PRIVATE KEY-----`
