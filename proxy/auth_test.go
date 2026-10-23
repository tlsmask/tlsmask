package proxy

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPasswordHashAtTheShippedCost(t *testing.T) {
	encoded, err := hashPassword("correct horse battery")
	if err != nil {
		t.Fatalf("hashPassword() error: %v", err)
	}
	if !strings.Contains(encoded, "$600000$") {
		t.Errorf("the hash was not derived at the documented cost: %s", encoded)
	}
	if !verifyPassword(encoded, "correct horse battery") {
		t.Error("the right password did not verify")
	}
}

func TestPasswordHashRoundTrip(t *testing.T) {
	cheapHashing(t)

	encoded, err := hashPassword("correct horse battery")
	if err != nil {
		t.Fatalf("hashPassword() error: %v", err)
	}
	if !verifyPassword(encoded, "correct horse battery") {
		t.Error("the right password did not verify")
	}
	if verifyPassword(encoded, "correct horse batter") {
		t.Error("a wrong password verified")
	}
	if verifyPassword("", "correct horse battery") {
		t.Error("an empty hash verified")
	}
	if verifyPassword("plaintext", "plaintext") {
		t.Error("an unencoded hash verified, so a hand-edited auth.json would be a password")
	}
}

func TestSetupNeedsTheTokenFromElsewhere(t *testing.T) {
	a := newTestAuth(t)
	token := a.SetupToken()
	if token == "" {
		t.Fatal("a fresh store minted no setup token")
	}

	if _, err := a.Setup("hunter2hunter2", "", false); err == nil {
		t.Error("setup from another host was allowed without the token")
	}
	if _, err := a.Setup("hunter2hunter2", "not-the-token", false); err == nil {
		t.Error("setup from another host was allowed with a wrong token")
	}
	if _, err := a.Setup("short", token, false); err == nil {
		t.Error("a password under the minimum length was accepted")
	}

	session, err := a.Setup("hunter2hunter2", token, false)
	if err != nil {
		t.Fatalf("Setup() with the right token: %v", err)
	}
	if !a.ValidSession(session) {
		t.Error("Setup() returned a session that is not valid")
	}
	if a.SetupToken() != "" {
		t.Error("the setup token survived setup")
	}
	if user, password := a.ProxyCredentials(); user == "" || password == "" {
		t.Error("setup did not generate proxy credentials")
	}
	if _, err := a.Setup("anotherpassword", "", true); err == nil {
		t.Error("a second setup was allowed, so an unattended restart could be claimed twice")
	}
}

func TestSetupFromThisMachineNeedsNoToken(t *testing.T) {
	a := newTestAuth(t)
	if _, err := a.Setup("hunter2hunter2", "", true); err != nil {
		t.Fatalf("Setup() from loopback: %v", err)
	}
}

func TestCredentialsPersist(t *testing.T) {
	cheapHashing(t)
	dir := t.TempDir()

	first, err := OpenAuth(dir)
	if err != nil {
		t.Fatalf("OpenAuth(): %v", err)
	}
	tokenPath := first.TokenPath()
	if _, err := os.Stat(tokenPath); err != nil {
		t.Fatalf("the setup token was not written where the UI says to find it: %v", err)
	}
	if _, err := first.Setup("hunter2hunter2", first.SetupToken(), false); err != nil {
		t.Fatalf("Setup(): %v", err)
	}
	if _, err := os.Stat(tokenPath); !os.IsNotExist(err) {
		t.Error("the setup token file outlived setup")
	}

	again, err := OpenAuth(dir)
	if err != nil {
		t.Fatalf("OpenAuth() after a restart: %v", err)
	}
	if !again.Configured() {
		t.Fatal("the password did not survive a restart")
	}
	u1, p1 := first.ProxyCredentials()
	u2, p2 := again.ProxyCredentials()
	if u1 != u2 || p1 != p2 {
		t.Error("the proxy credentials changed across a restart, which would break every client")
	}
	if again.SetupToken() != "" {
		t.Error("a configured store minted a setup token, reopening first-run setup")
	}

	if again.ValidSession("") || again.ValidSession("made-up") {
		t.Error("an unknown cookie was accepted")
	}

	if _, err := os.Stat(filepath.Join(dir, authFile)); err != nil {
		t.Errorf("auth.json is not where it should be: %v", err)
	}
}

func TestLoginLocksOutAfterRepeatedFailures(t *testing.T) {
	a := newTestAuth(t)
	if _, err := a.Setup("hunter2hunter2", "", true); err != nil {
		t.Fatalf("Setup(): %v", err)
	}

	for i := range loginMaxFails {
		if _, err := a.Login("wrong", "10.0.0.5:51000"); err == nil {
			t.Fatalf("attempt %d with a wrong password succeeded", i+1)
		}
	}
	if _, err := a.Login("hunter2hunter2", "10.0.0.5:51000"); err == nil {
		t.Error("the right password was accepted during the lockout")
	}

	if _, err := a.Login("hunter2hunter2", "10.0.0.6:51000"); err != nil {
		t.Errorf("a different client was locked out too: %v", err)
	}
}

func TestChangePasswordSignsEveryoneOut(t *testing.T) {
	a := newTestAuth(t)
	session, err := a.Setup("hunter2hunter2", "", true)
	if err != nil {
		t.Fatalf("Setup(): %v", err)
	}

	if err := a.ChangePassword("wrong", "replacementpassword"); err == nil {
		t.Error("the password changed without the current one")
	}
	if err := a.ChangePassword("hunter2hunter2", "replacementpassword"); err != nil {
		t.Fatalf("ChangePassword(): %v", err)
	}
	if a.ValidSession(session) {
		t.Error("a session outlived the password it was issued against")
	}
}

func TestProxyCredentialChecks(t *testing.T) {
	a := newTestAuth(t)
	if _, err := a.Setup("hunter2hunter2", "", true); err != nil {
		t.Fatalf("Setup(): %v", err)
	}
	user, password := a.ProxyCredentials()
	if user == "" || password == "" {
		t.Fatalf("setup left the proxy credentials empty: %q / %q", user, password)
	}

	if !a.CheckProxyCredentials(user, password) {
		t.Error("the generated credentials were rejected")
	}
	for _, bad := range [][2]string{
		{user, password + "0"},
		{user, ""},
		{"", password},
		{user + "x", password},
		{password, user},
	} {
		if a.CheckProxyCredentials(bad[0], bad[1]) {
			t.Errorf("credentials %q / %q were accepted", bad[0], bad[1])
		}
	}

	rotated, err := a.RotateProxyPassword()
	if err != nil {
		t.Fatalf("RotateProxyPassword(): %v", err)
	}
	if rotated == password {
		t.Error("regenerating returned the same password")
	}
	if a.CheckProxyCredentials(user, password) {
		t.Error("the old password still works after it was regenerated")
	}
	if again, _ := a.ProxyCredentials(); again != user {
		t.Errorf("regenerating the password changed the username from %q to %q", user, again)
	}
}

func TestServerRefusesWithoutCredentials(t *testing.T) {
	a := newTestAuth(t)
	srv := &Server{Addr: "0.0.0.0:2255", Auth: a}

	req := &http.Request{Method: http.MethodConnect, Header: make(http.Header), Host: "example.com:443"}
	reason, ok := srv.checkProxyAuth(req)
	if ok {
		t.Fatal("a request was allowed before setup, which would leave the proxy open on a fresh install")
	}
	if reason == "" {
		t.Error("the refusal carried no reason")
	}

	if _, err := a.Setup("hunter2hunter2", "", true); err != nil {
		t.Fatalf("Setup(): %v", err)
	}
	user, password := a.ProxyCredentials()

	if _, ok := srv.checkProxyAuth(req); ok {
		t.Error("a request with no credentials was allowed")
	}

	req.Header.Set("Proxy-Authorization", password)
	if _, ok := srv.checkProxyAuth(req); ok {
		t.Error("a bare password with no Basic scheme was accepted")
	}

	viaURL := authRequest(user, password)
	viaURL.Method = http.MethodConnect
	if reason, ok := srv.checkProxyAuth(viaURL); !ok {
		t.Errorf("the credentials from a proxy URL were refused: %s", reason)
	}

	withSession := authRequest(user+"-session-a1b2c3", password)
	withSession.Method = http.MethodConnect
	if reason, ok := srv.checkProxyAuth(withSession); !ok {
		t.Errorf("a username carrying a session was refused: %s", reason)
	}

	open := &Server{Addr: "0.0.0.0:2255"}
	if _, ok := open.checkProxyAuth(&http.Request{Method: http.MethodConnect, Header: make(http.Header)}); !ok {
		t.Error("a Server with no AuthStore refused a request")
	}
}

func TestControlAPITakesOrdinaryBasicAuth(t *testing.T) {
	a := newTestAuth(t)
	if _, err := a.Setup("hunter2hunter2", "", true); err != nil {
		t.Fatalf("Setup(): %v", err)
	}
	user, password := a.ProxyCredentials()
	srv := &Server{Addr: "0.0.0.0:2255", Auth: a}

	req := &http.Request{Method: http.MethodDelete, Header: make(http.Header)}
	req.Header.Set("Authorization", basic(user, password))
	if reason, ok := srv.checkControlAuth(req); !ok {
		t.Errorf("Authorization: Basic was refused on the control API: %s", reason)
	}
	if _, ok := srv.checkProxyAuth(req); ok {
		t.Error("Authorization was taken as proxy credentials on a request going through")
	}
}

func TestLegacyKeyIsCarriedOver(t *testing.T) {
	cheapHashing(t)
	dir := t.TempDir()

	hash, err := hashPassword("hunter2hunter2")
	if err != nil {
		t.Fatalf("hashPassword(): %v", err)
	}
	legacy := `{"password":"` + hash + `","proxyKey":"0123456789abcdef0123456789abcdef"}`
	if err := os.WriteFile(filepath.Join(dir, authFile), []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}

	a, err := OpenAuth(dir)
	if err != nil {
		t.Fatalf("OpenAuth() on an older file: %v", err)
	}
	user, password := a.ProxyCredentials()
	if password != "0123456789abcdef0123456789abcdef" {
		t.Errorf("the old key was not kept as the proxy password: %q", password)
	}
	if user == "" {
		t.Error("no username was generated to go with it")
	}
	if !a.Configured() {
		t.Error("upgrading lost the UI password")
	}

	raw, _ := os.ReadFile(filepath.Join(dir, authFile))
	if strings.Contains(string(raw), "proxyKey") {
		t.Error("the upgraded file still carries the legacy field")
	}
}

func cheapHashing(t *testing.T) {
	t.Helper()

	was := pbkdf2Iterations
	pbkdf2Iterations = 4096
	t.Cleanup(func() { pbkdf2Iterations = was })
}

func newTestAuth(t *testing.T) *AuthStore {
	t.Helper()
	cheapHashing(t)

	a, err := OpenAuth(t.TempDir())
	if err != nil {
		t.Fatalf("OpenAuth(): %v", err)
	}
	return a
}

func TestResetPasswordReachesTheRunningServer(t *testing.T) {
	cheapHashing(t)
	dir := t.TempDir()

	running, err := OpenAuth(dir)
	if err != nil {
		t.Fatalf("OpenAuth(): %v", err)
	}
	session, err := running.Setup("hunter2hunter2", "", true)
	if err != nil {
		t.Fatalf("Setup(): %v", err)
	}
	user, password := running.ProxyCredentials()

	token, err := ResetPassword(dir)
	if err != nil {
		t.Fatalf("ResetPassword(): %v", err)
	}
	if token == "" {
		t.Fatal("ResetPassword() returned no setup token")
	}

	running.checkedAt = time.Time{}

	if running.Configured() {
		t.Fatal("the running server still has the old password after a reset")
	}
	if got := running.SetupToken(); got != token {
		t.Errorf("the server expects setup token %q, the command printed %q", got, token)
	}
	if running.ValidSession(session) {
		t.Error("a browser signed in before the reset is still signed in")
	}
	if u, p := running.ProxyCredentials(); u != user || p != password {
		t.Error("the reset changed the proxy credentials, which would break every client")
	}

	srv := &Server{Addr: "0.0.0.0:2255", Auth: running}
	req := authRequest(user, password)
	req.Method = http.MethodConnect
	if reason, ok := srv.checkProxyAuth(req); !ok {
		t.Errorf("the proxy refused valid credentials while the password was reset: %s", reason)
	}

	if _, err := running.Setup("anotherpassword", token, false); err != nil {
		t.Fatalf("Setup() after a reset: %v", err)
	}
	if u, p := running.ProxyCredentials(); u != user || p != password {
		t.Error("setting a new password generated new proxy credentials")
	}
	if _, err := running.Login("hunter2hunter2", "10.0.0.9:1"); err == nil {
		t.Error("the old password still signs in")
	}
	if _, err := running.Login("anotherpassword", "10.0.0.9:1"); err != nil {
		t.Errorf("the new password does not sign in: %v", err)
	}
}

func TestResetPasswordWithoutADataDirSaysWhy(t *testing.T) {
	if _, err := ResetPassword(""); err == nil {
		t.Error("a memory-only install reported a reset that cannot have happened")
	}
}
