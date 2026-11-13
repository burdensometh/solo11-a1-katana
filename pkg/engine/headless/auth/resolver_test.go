package auth

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSelectorKeywords(t *testing.T) {
	tests := []struct {
		name     string
		selector string
		want     []string
	}{
		{
			name:     "css id with hyphen",
			selector: "#user-email",
			want:     []string{"user", "email"},
		},
		{
			name:     "quoted attribute value",
			selector: `input[aria-label="Email address"]`,
			want:     []string{"email", "address"},
		},
		{
			name:     "xpath with quoted id",
			selector: `xpath=//*[@id="login-password-field"]`,
			want:     []string{"login", "password", "field"},
		},
		{
			name:     "name selector strips stopwords",
			selector: `input[name=passwd]`,
			want:     []string{"passwd"},
		},
		{
			name:     "underscore token",
			selector: "#login_form_submit_button",
			want:     []string{"login", "submit"},
		},
		{
			name:     "empty",
			selector: "   ",
			want:     nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := selectorKeywords(tt.selector)
			for _, want := range tt.want {
				require.Contains(t, got, want, "selector %q should yield keyword %q", tt.selector, want)
			}
		})
	}
}

func TestSelectorKeywords_DedupAndCapped(t *testing.T) {
	keywords := selectorKeywords(`#email-email-email-email-email-email-email-email-email-email-email-email`)
	require.Len(t, keywords, 1)
	require.Equal(t, "email", keywords[0])

	long := selectorKeywords(`#a-b-c-d-e-f-g-h-i-j-k-l-m-n-o-p`)
	require.LessOrEqual(t, len(long), 8)
}

func TestTagsForAction(t *testing.T) {
	require.Equal(t, []string{"input", "textarea", "select", "[contenteditable]"},
		tagsForAction("fill", "#x"))
	require.Contains(t, tagsForAction("click", "#x"), "button")
	require.Nil(t, tagsForAction("waitvisible", "#x"))
}

func TestMatchRuleConstants(t *testing.T) {
	// Rule names are recorded into flow diagnostics; pin them so downstream
	// log parsers do not silently break.
	require.Equal(t, "selector", MatchRuleSelector)
	require.Equal(t, "label", MatchRuleLabel)
	require.Equal(t, "sibling", MatchRuleSibling)
}

func TestLabelHints_FromChromeAlternatives(t *testing.T) {
	groups := [][]string{
		{"#submit"},
		{"aria/Sign in"},
		{"text/Sign in"},
	}
	require.Equal(t, []string{"Sign in"}, labelHints(groups))
	require.Empty(t, labelHints([][]string{{"#x"}, {"xpath///button"}}))

	// Quoted text cannot be safely embedded downstream; it is skipped.
	require.Empty(t, labelHints([][]string{{`aria/He said "go"`}}))
}

func TestLabelKeywords_HintsLeadSelectorWords(t *testing.T) {
	r := &stepResolver{}
	kw := r.labelKeywords(LoginStep{
		Selector:   "#submit",
		LabelHints: []string{"Sign in"},
	})
	require.Equal(t, []string{"sign in", "submit"}, kw)
}
