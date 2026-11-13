package auth_test

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/launcher"
	"github.com/go-rod/rod/lib/proto"
	"github.com/projectdiscovery/katana/internal/testutils/authlab"
	"github.com/projectdiscovery/katana/pkg/engine/headless/auth"
	"github.com/stretchr/testify/require"
)

func skipIfNoBrowser(t *testing.T) {
	t.Helper()
	if path, found := launcher.LookPath(); !found || path == "" {
		t.Skip("chrome/chromium not found, skipping recorded-flow e2e")
	}
}

func launchPage(t *testing.T) (*rod.Browser, *rod.Page) {
	t.Helper()
	skipIfNoBrowser(t)

	path, _ := launcher.LookPath()
	u := launcher.New().
		Bin(path).
		Headless(true).
		Leakless(true).
		Set("no-sandbox", "true").
		MustLaunch()
	browser := rod.New().ControlURL(u).MustConnect()
	t.Cleanup(browser.MustClose)

	page, err := browser.Page(proto.TargetCreateTarget{})
	require.NoError(t, err)
	t.Cleanup(func() { _ = page.Close() })
	return browser, page
}

func writeFlow(t *testing.T, contents string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "flow.json")
	require.NoError(t, os.WriteFile(path, []byte(contents), 0o600))
	return path
}

func assertSecretReachable(t *testing.T, page *rod.Page, lab *authlab.Lab) {
	t.Helper()
	require.NoError(t, page.Navigate(lab.URL+"/app/secret"))
	require.NoError(t, page.WaitLoad())
	html, err := page.HTML()
	require.NoError(t, err)
	require.Contains(t, html, authlab.SecretMarker, "session from recorded flow should unlock /app/secret")
	require.GreaterOrEqual(t, lab.SecretHits.Load(), int64(1))
}

func TestE2E_RecordedFlow_SimpleFormLogin(t *testing.T) {
	lab, err := authlab.Start()
	require.NoError(t, err)
	t.Cleanup(func() { _ = lab.Close() })

	_, page := launchPage(t)
	path := writeFlow(t, authlab.ChromeRecordingSimple(lab.URL))

	steps, err := auth.StepsFromFile(path, authlab.Username, authlab.Password)
	require.NoError(t, err)
	require.NotEmpty(t, steps)
	require.True(t, auth.NeedsCredentials(steps))

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	require.NoError(t, auth.RunLoginSteps(ctx, page, steps, authlab.Username, authlab.Password, 5*time.Second))
	require.GreaterOrEqual(t, lab.LoginPosts.Load(), int64(1))
	assertSecretReachable(t, page, lab)
}

func TestE2E_RecordedFlow_UsernameFirst(t *testing.T) {
	lab, err := authlab.Start()
	require.NoError(t, err)
	t.Cleanup(func() { _ = lab.Close() })

	_, page := launchPage(t)
	path := writeFlow(t, authlab.ChromeRecordingStep(lab.URL))

	steps, err := auth.StepsFromFile(path, authlab.Username, authlab.Password)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	require.NoError(t, auth.RunLoginSteps(ctx, page, steps, authlab.Username, authlab.Password, 5*time.Second))
	assertSecretReachable(t, page, lab)
}

func TestE2E_RecordedFlow_SPA(t *testing.T) {
	lab, err := authlab.Start()
	require.NoError(t, err)
	t.Cleanup(func() { _ = lab.Close() })

	_, page := launchPage(t)
	path := writeFlow(t, authlab.ChromeRecordingSPA(lab.URL))

	steps, err := auth.StepsFromFile(path, authlab.Username, authlab.Password)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	require.NoError(t, auth.RunLoginSteps(ctx, page, steps, authlab.Username, authlab.Password, 5*time.Second))
	assertSecretReachable(t, page, lab)
}

func TestE2E_RecordedFlow_ExplicitSteps(t *testing.T) {
	lab, err := authlab.Start()
	require.NoError(t, err)
	t.Cleanup(func() { _ = lab.Close() })

	_, page := launchPage(t)
	path := writeFlow(t, authlab.ExplicitStepsSimple(lab.URL))

	steps, err := auth.StepsFromFile(path, authlab.Username, authlab.Password)
	require.NoError(t, err)
	require.Equal(t, "navigate", steps[0].Action)
	require.Equal(t, "{{username}}", steps[1].Value)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	require.NoError(t, auth.RunLoginSteps(ctx, page, steps, authlab.Username, authlab.Password, 5*time.Second))
	assertSecretReachable(t, page, lab)
}

// TestE2E_RecordedFlow_RedesignLabelAndSiblingFallback replays selectors
// recorded against the old login page against a redesigned page where every
// recorded id is gone. It asserts the flow still logs in and that each step
// records the rule that actually located its element.
func TestE2E_RecordedFlow_RedesignLabelAndSiblingFallback(t *testing.T) {
	lab, err := authlab.Start()
	require.NoError(t, err)
	t.Cleanup(func() { _ = lab.Close() })

	_, page := launchPage(t)
	path := writeFlow(t, authlab.ExplicitStepsRedesign(lab.URL))

	steps, err := auth.StepsFromFile(path, authlab.Username, authlab.Password)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	require.NoError(t, auth.RunLoginSteps(ctx, page, steps, authlab.Username, authlab.Password, 5*time.Second))
	assertSecretReachable(t, page, lab)

	// steps: navigate, fill email, fill password, click submit. The hand
	// authored flow carries no label hints. The two inputs are recovered via
	// label semantics (the email input's type, then the password input type);
	// the textless button has no label signal so it falls to sibling structure.
	require.Equal(t, auth.MatchRuleLabel, steps[1].MatchRule, "email field recovered via label/type semantics")
	require.Contains(t, steps[1].MatchedSelector, "input")
	require.Equal(t, auth.MatchRuleLabel, steps[2].MatchRule, "password field recovered via label/type semantics")
	require.Contains(t, steps[2].MatchedSelector, "input")
	require.Equal(t, auth.MatchRuleSibling, steps[3].MatchRule, "submit button recovered via adjacent structure")
	require.Contains(t, steps[3].MatchedSelector, "button")
}

// TestE2E_RecordedFlow_RedesignChromeRecording exercises the same fallback
// chain through a Chrome Recorder export (compiled via pickSelector).
func TestE2E_RecordedFlow_RedesignChromeRecording(t *testing.T) {
	lab, err := authlab.Start()
	require.NoError(t, err)
	t.Cleanup(func() { _ = lab.Close() })

	_, page := launchPage(t)
	path := writeFlow(t, authlab.ChromeRecordingRedesign(lab.URL))

	steps, err := auth.StepsFromFile(path, authlab.Username, authlab.Password)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	require.NoError(t, auth.RunLoginSteps(ctx, page, steps, authlab.Username, authlab.Password, 5*time.Second))
	assertSecretReachable(t, page, lab)

	// The recording carries real label text ("Sign in"), so the button is
	// recovered through the label rule rather than structural fallback.
	rules := []string{steps[1].MatchRule, steps[2].MatchRule, steps[3].MatchRule}
	require.Equal(t, []string{auth.MatchRuleLabel, auth.MatchRuleLabel, auth.MatchRuleLabel}, rules)
}

// TestE2E_RecordedFlow_OriginalSelectorStillWinsWhenPresent pins tier 1: when
// the recorded selector still matches, no fallback rule is recorded.
func TestE2E_RecordedFlow_OriginalSelectorStillWinsWhenPresent(t *testing.T) {
	lab, err := authlab.Start()
	require.NoError(t, err)
	t.Cleanup(func() { _ = lab.Close() })

	_, page := launchPage(t)
	path := writeFlow(t, authlab.ExplicitStepsSimple(lab.URL))

	steps, err := auth.StepsFromFile(path, authlab.Username, authlab.Password)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	require.NoError(t, auth.RunLoginSteps(ctx, page, steps, authlab.Username, authlab.Password, 5*time.Second))

	for i := 1; i < len(steps); i++ {
		require.Equal(t, auth.MatchRuleSelector, steps[i].MatchRule,
			"step %d should keep using its recorded selector", i)
		require.NotEmpty(t, steps[i].MatchedSelector)
	}
}

// TestE2E_RecordedFlow_StructureOnlyRedesign targets a page with no label
// text at all. The two inputs are recovered from their semantic input types
// (label tier); the empty, textless submit button has no label signal, so it
// is reconstructed from the previously matched element's sibling structure.
func TestE2E_RecordedFlow_StructureOnlyRedesign(t *testing.T) {
	lab, err := authlab.Start()
	require.NoError(t, err)
	t.Cleanup(func() { _ = lab.Close() })

	_, page := launchPage(t)
	path := writeFlow(t, authlab.ExplicitStepsStructureOnly(lab.URL))

	steps, err := auth.StepsFromFile(path, authlab.Username, authlab.Password)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	require.NoError(t, auth.RunLoginSteps(ctx, page, steps, authlab.Username, authlab.Password, 5*time.Second))
	assertSecretReachable(t, page, lab)

	require.Equal(t, auth.MatchRuleLabel, steps[1].MatchRule, "unlabeled email field recovered via input type")
	require.Equal(t, auth.MatchRuleLabel, steps[2].MatchRule, "unlabeled password field recovered via input type")
	require.Equal(t, auth.MatchRuleSibling, steps[3].MatchRule, "textless submit button recovered via sibling")
}

func TestE2E_RecordedFlow_WrongPasswordDoesNotUnlockSecret(t *testing.T) {
	lab, err := authlab.Start()
	require.NoError(t, err)
	t.Cleanup(func() { _ = lab.Close() })

	_, page := launchPage(t)
	path := writeFlow(t, authlab.ChromeRecordingSimple(lab.URL))

	steps, err := auth.StepsFromFile(path, authlab.Username, authlab.Password)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	// Replay with wrong password — form submit may "succeed" as clicks, but
	// the session cookie must not be issued.
	_ = auth.RunLoginSteps(ctx, page, steps, authlab.Username, "wrong-password", 5*time.Second)

	require.NoError(t, page.Navigate(lab.URL+"/app/secret"))
	require.NoError(t, page.WaitLoad())
	html, err := page.HTML()
	require.NoError(t, err)
	require.NotContains(t, html, authlab.SecretMarker)
	require.Equal(t, int64(0), lab.SecretHits.Load())
}

func TestE2E_RecordedFlow_LocalStorageSessionIsDetected(t *testing.T) {
	_, page := launchPage(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = fmt.Fprint(w, `<button id="login" onclick="localStorage.setItem('access_token', 'opaque-token')">Login</button>`)
	}))
	t.Cleanup(server.Close)

	require.NoError(t, page.Navigate(server.URL))
	require.NoError(t, page.WaitLoad())
	before, err := auth.CaptureSessionState(page)
	require.NoError(t, err)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	require.NoError(t, auth.RunLoginSteps(ctx, page, []auth.LoginStep{
		{Action: "click", Selector: "#login"},
	}, "", "", time.Second))

	after, err := auth.CaptureSessionState(page)
	require.NoError(t, err)
	require.True(t, auth.SessionStateChanged(before, after),
		"same-origin localStorage token should verify a cookie-less login")
}

func TestE2E_RecordedFlow_AllExplicitActions(t *testing.T) {
	_, page := launchPage(t)
	lab, err := authlab.Start()
	require.NoError(t, err)
	t.Cleanup(func() { _ = lab.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	require.NoError(t, auth.RunLoginSteps(ctx, page, []auth.LoginStep{
		{Action: "navigate", Value: lab.URL + "/login"},
		{Action: "fill", Selector: "#email", Value: "{{username}}"},
		{Action: "fill", Selector: "#password", Value: "{{password}}"},
		{Action: "click", Selector: "#email"},
		{Action: "doubleclick", Selector: "#email"},
		{Action: "waitvisible", Selector: "#password"},
		{Action: "press", Selector: "#password", Value: "tab"},
		{Action: "wait", Value: "1ms"},
		{Action: "submit", Selector: "#submit"},
		{Action: "waitvisible", Selector: "h1"},
	}, authlab.Username, authlab.Password, 2*time.Second))

	cookies, err := page.Browser().GetCookies()
	require.NoError(t, err)
	foundSession := false
	for _, cookie := range cookies {
		if cookie.Name == authlab.CookieName && cookie.Value == authlab.CookieValue {
			foundSession = true
			break
		}
	}
	require.True(t, foundSession)
}

func TestE2E_RecordedFlow_WaitHonorsCancellation(t *testing.T) {
	_, page := launchPage(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	started := time.Now()
	err := auth.RunLoginSteps(ctx, page, []auth.LoginStep{
		{Action: "wait", Value: "10s"},
	}, "", "", time.Second)
	require.ErrorIs(t, err, context.Canceled)
	require.Less(t, time.Since(started), time.Second)
}

func TestE2E_RecordedFlow_NavigateHonorsCancellation(t *testing.T) {
	_, page := launchPage(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		time.Sleep(5 * time.Second)
		_, _ = fmt.Fprint(w, "late")
	}))
	t.Cleanup(server.Close)

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	started := time.Now()
	err := auth.RunLoginSteps(ctx, page, []auth.LoginStep{
		{Action: "navigate", Value: server.URL},
	}, "", "", 10*time.Second)
	require.Error(t, err)
	require.Less(t, time.Since(started), 2*time.Second)
}
