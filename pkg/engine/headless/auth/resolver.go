package auth

import (
	"log/slog"
	"regexp"
	"strings"

	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
)

// loginLog receives diagnostics about fallback selector hits. It defaults to
// the process slog logger and can be redirected by embedders that want the
// messages alongside their crawler output.
var loginLog *slog.Logger = slog.Default()

// Match rules recorded on LoginStep.MatchRule when the original recorded
// selector no longer matches the live page after a site redesign.
const (
	// MatchRuleSelector: the original recorded selector (or its input[name=…]
	// equivalent) still resolves to a visible element.
	MatchRuleSelector = "selector"
	// MatchRuleLabel: the original selector failed, but an element was located
	// via its associated <label> text / aria-label / placeholder.
	MatchRuleLabel = "label"
	// MatchRuleSibling: the label strategy failed as well, so the element was
	// reconstructed from the DOM position relative to the previous element the
	// flow successfully interacted with (same label row, then sibling inputs).
	MatchRuleSibling = "sibling"
)

// Match describes how a single step's element was resolved during replay.
type Match struct {
	// StepIndex is the zero-based index of the step in the replayed flow.
	StepIndex int
	// Rule is one of MatchRuleSelector / MatchRuleLabel / MatchRuleSibling.
	Rule string
	// Selector is the selector the step originally recorded.
	Selector string
	// Resolved is a best-effort tag#id[name=…] description of the hit element.
	Resolved string
}

// resolverHelperJS installs the DOM helpers used by the label and sibling
// fallback strategies. Installed once per page; re-installation is harmless.
const resolverHelperJS = `() => {
  if (window.__katanaResolve) { return; }

  const isVisible = (el) => {
    if (!el || !el.getClientRects) { return false; }
    if (el.getClientRects().length === 0) { return false; }
    const style = window.getComputedStyle(el);
    if (style.visibility === "hidden" || style.display === "none" ||
        style.opacity === "0" || Number(style.pointerEvents === "none") === 1) {
      return false;
    }
    const rect = el.getBoundingClientRect();
    return rect.width > 0 && rect.height > 0;
  };

  const norm = (s) => (s || "").replace(/\s+/g, " ").trim().toLowerCase();

  const scoreText = (text, keywords) => {
    text = norm(text);
    if (!text) { return 0; }
    let best = 0;
    for (const kw of keywords) {
      const k = norm(kw);
      if (!k) { continue; }
      if (text === k) { best = Math.max(best, 100 + k.length); }
      else if (text.includes(k)) { best = Math.max(best, 50 + k.length); }
      else if (k.includes(text) && text.length >= 3) { best = Math.max(best, 20 + text.length); }
    }
    return best;
  };

  // Interactive controls that a login-flow step can plausibly target.
  const controlSelector =
    "input, textarea, select, button, a[href], [role=button], [contenteditable=true]";

  // matchesTags checks a control against the action-derived filter. Plain tag
  // names ("input", "button") compare against tagName; CSS-ish filters such as
  // "[role=button]" are tested with Element.matches.
  const matchesTags = (el, tags) => {
    if (!tags || tags.length === 0) { return true; }
    for (const t of tags) {
      if (t.includes("[")) {
        try { if (el.matches(t)) { return true; } } catch (e) { /* invalid filter */ }
      } else if (el.tagName === t.toUpperCase()) {
        return true;
      }
    }
    return false;
  };


  const controlText = (el) => {
    const parts = [];
    const push = (v) => { v = norm(v); if (v) { parts.push(v); } };
    push(el.getAttribute("aria-label"));
    push(el.getAttribute("placeholder"));
    push(el.getAttribute("title"));
    if (el.labels) {
      for (const label of el.labels) { push(label.textContent); }
    }
    const id = el.getAttribute("id");
    if (id) {
      for (const label of document.querySelectorAll("label[for]")) {
        if (label.getAttribute("for") === id) { push(label.textContent); }
      }
    }
    // Wrapping label without a for= attribute.
    const wrapper = el.closest("label");
    if (wrapper) { push(wrapper.textContent); }
    if (el.tagName === "BUTTON" || el.tagName === "A") { push(el.textContent); }
    return parts.join(" ");
  };

  window.__katanaResolve = {
    // findByLabel returns the visible control whose label text / aria-label /
    // placeholder best matches the keywords derived from the dead selector.
    findByLabel(keywords, tags) {
      let best = null;
      let bestScore = 0;
      for (const el of document.querySelectorAll(controlSelector)) {
        if (!isVisible(el)) { continue; }
        if (!matchesTags(el, tags)) { continue; }
        if (el.disabled) { continue; }
        const score = scoreText(controlText(el), keywords);
        if (score > bestScore) {
          bestScore = score;
          best = el;
        }
      }
      return bestScore > 0 ? best : null;
    },

    // findByInputType is the label-tier's last resort for forms whose controls
    // have no label text at all. It matches a keyword's semantic intent against
    // the input type/name/autocomplete (keyword "email" → type=email,
    // "password" → type=password), which survives visual redesigns.
    findByInputType(keywords, tags) {
      const wants = (el, words) => {
        const hay = [
          el.type || "", el.name || "", el.id || "",
          el.getAttribute("autocomplete") || "",
        ].join(" ").toLowerCase();
        return words.some((w) => hay.includes(w));
      };
      const kw = (keywords || []).map((k) => norm(k));
      const passwordish = ["password", "passwd", "pwd"];
      const emailish = ["email", "e-mail", "mail", "username", "user-name", "user", "login"];
      for (const el of document.querySelectorAll(controlSelector)) {
        if (!isVisible(el) || !matchesTags(el, tags) || el.disabled) { continue; }
        if (kw.some((k) => passwordish.includes(k)) &&
            (el.type === "password" || wants(el, passwordish))) {
          return el;
        }
      }
      for (const el of document.querySelectorAll(controlSelector)) {
        if (!isVisible(el) || !matchesTags(el, tags) || el.disabled) { continue; }
        if (el.type === "password") { continue; }
        if (kw.some((k) => emailish.includes(k)) &&
            (el.type === "email" || el.type === "text" || wants(el, emailish))) {
          return el;
        }
      }
      return null;
    },

    // findBySibling reconstructs a control relative to anchor (the previous
    // successfully matched element). It first looks inside the enclosing label
    // / form-row container, then at following and preceding sibling controls,
    // then at descendants / controls within a bounded number of parent steps.
    findBySibling(anchor, tags) {
      if (!anchor || !anchor.isConnected) { return null; }
      const acceptable = (el) =>
        el && el !== anchor && el.nodeType === 1 && isVisible(el) &&
        matchesTags(el, tags) && !el.disabled;

      // 1. Another control inside the same label/row container.
      const row = anchor.closest("label, .field, .form-field, .form-group, .row, li, td, div");
      if (row && row !== anchor) {
        for (const candidate of row.querySelectorAll(controlSelector)) {
          if (acceptable(candidate)) { return candidate; }
        }
      }

      // 2. Walk up a bounded number of ancestors and inspect each level's
      // subtree in document order, preferring the tightest enclosing scope.
      let parent = anchor.parentElement;
      for (let depth = 0; parent && depth < 3; depth++) {
        const controls = parent.querySelectorAll(controlSelector);
        const index = Array.prototype.indexOf.call(controls, anchor);
        // First the controls that follow the anchor inside this container…
        for (let i = index + 1; i < controls.length; i++) {
          if (acceptable(controls[i])) { return controls[i]; }
        }
        // …then the ones preceding it.
        for (let i = index - 1; i >= 0; i--) {
          if (acceptable(controls[i])) { return controls[i]; }
        }
        parent = parent.parentElement;
      }
      return null;
    }
  };
}`

// stepResolver locates elements for replay steps. It applies the recorded
// selector first and, when that selector has gone stale after a site redesign,
// falls back to label-text matching and finally DOM-position (sibling)
// matching, tracking which rule won for diagnostics.
type stepResolver struct {
	page *rod.Page

	// lastAnchor is the previous element any rule resolved successfully, used
	// as the structural anchor for the sibling fallback.
	lastAnchor *rod.Element

	// lastStep caches the result for the step currently being resolved so
	// waitvisible polling does not re-run fallbacks or move the anchor.
	lastStep int
	lastHit  *resolveResult

	mu []Match
}

func newStepResolver(page *rod.Page) *stepResolver {
	r := &stepResolver{page: page, lastStep: -1}
	r.ensureHelper()
	return r
}

// ensureHelper (re)installs the DOM helpers. SPA panel swaps and client-side
// re-renders can discard window globals, so resolution re-checks each time.
// Failure here only disables the fallback rules; the original selector tier
// still works.
func (r *stepResolver) ensureHelper() {
	present, err := r.page.Eval(`() => typeof window.__katanaResolve === "object"`)
	if err == nil && present != nil && present.Value.Bool() {
		return
	}
	_ = rod.Try(func() {
		r.page.MustEval(resolverHelperJS)
	})
}

// Matches returns the per-step resolution record for every step that found an
// element, in replay order.
func (r *stepResolver) Matches() []Match {
	return append([]Match(nil), r.mu...)
}

// resolveResult is what a strategy returns.
type resolveResult struct {
	el       *rod.Element
	rule     string
	resolved string
}

// Resolve finds an element for step using the three-tier strategy. action is
// the normalized step action used to constrain fallback tag candidates.
// A successful resolution is cached so waitvisible polling does not re-run
// fallbacks or move the anchor; a miss stays retryable for later polls.
func (r *stepResolver) Resolve(stepIndex int, step LoginStep, action string) *resolveResult {
	if r.lastStep == stepIndex && r.lastHit != nil {
		return r.lastHit
	}
	hit := r.resolve(stepIndex, step, action)
	if hit != nil {
		r.lastStep = stepIndex
		r.lastHit = hit
	}
	return hit
}

func (r *stepResolver) resolve(stepIndex int, step LoginStep, action string) *resolveResult {
	r.ensureHelper()
	original := strings.TrimSpace(step.Selector)

	// Tier 1: the recorded selector itself (plus the input[name=…] shorthand
	// used by fill/press steps).
	var primary []string
	if nameSel := byName(original); nameSel != "" {
		primary = append(primary, nameSel)
	}
	primary = append(primary, original)
	if el := findVisible(r.page, primary...); el != nil {
		return r.record(stepIndex, original, MatchRuleSelector, describeElement(el), el)
	}

	keywords := r.labelKeywords(step)

	// Tier 2: match by label text / aria-label / placeholder, then by the
	// input's semantic type/name when the control has no visible label at all.
	tags := tagsForAction(action, original)
	if len(keywords) > 0 {
		if el, ok := r.evalElement(`(kw, tags) => window.__katanaResolve.findByLabel(kw, tags)`,
			keywords, tags); ok && el != nil {
			return r.record(stepIndex, original, MatchRuleLabel, describeElement(el), el)
		}
		if el, ok := r.evalElement(`(kw, tags) => window.__katanaResolve.findByInputType(kw, tags)`,
			keywords, tags); ok && el != nil {
			return r.record(stepIndex, original, MatchRuleLabel, describeElement(el), el)
		}
	}

	// Tier 3: reconstruct from the previous successful element's position.
	if r.lastAnchor != nil {
		if el, ok := r.evalElementFrom(r.lastAnchor, `function (tags) {
			return window.__katanaResolve.findBySibling(this, tags);
		}`, tags); ok && el != nil {
			return r.record(stepIndex, original, MatchRuleSibling, describeElement(el), el)
		}
	}

	return nil
}

func (r *stepResolver) record(stepIndex int, selector, rule, resolved string, el *rod.Element) *resolveResult {
	r.lastAnchor = el
	r.mu = append(r.mu, Match{
		StepIndex: stepIndex,
		Rule:      rule,
		Selector:  selector,
		Resolved:  resolved,
	})
	return &resolveResult{el: el, rule: rule, resolved: resolved}
}

// evalElement runs a page-scope helper function that returns a DOM node and
// converts it into a rod element handle. ByObject keeps ByValue off so the
// result comes back as a remote object reference rather than a serialized
// value (a DOM node cannot be JSON-serialized).
func (r *stepResolver) evalElement(fn string, args ...interface{}) (*rod.Element, bool) {
	res, err := r.page.Evaluate(rod.Eval(fn, args...).ByPromise().ByObject())
	if err != nil || res == nil {
		return nil, false
	}
	return elementFromObject(r.page, res)
}

// evalElementFrom runs the helper with `this` bound to anchor, so the
// sibling strategy receives the live previous-success element.
func (r *stepResolver) evalElementFrom(anchor *rod.Element, fn string, tags []string) (*rod.Element, bool) {
	res, err := anchor.Evaluate(rod.Eval(fn, tags).ByPromise().ByObject())
	if err != nil || res == nil {
		return nil, false
	}
	return elementFromObject(r.page, res)
}

func elementFromObject(page *rod.Page, obj *proto.RuntimeRemoteObject) (*rod.Element, bool) {
	if obj == nil || obj.ObjectID == "" {
		return nil, false
	}
	el, err := page.ElementFromObject(obj)
	if err != nil || el == nil {
		return nil, false
	}
	return el, true
}

// describeElement renders a short tag#id[name=…] description for diagnostics.
func describeElement(el *rod.Element) string {
	if el == nil {
		return ""
	}
	desc, err := el.Eval(`function () {
		let s = this.tagName.toLowerCase();
		if (this.id) { s += "#" + this.id; }
		const name = this.getAttribute && this.getAttribute("name");
		if (name) { s += '[name="' + name + '"]'; }
		return s;
	}`)
	if err != nil || desc == nil {
		return ""
	}
	return strings.TrimSpace(desc.Value.Str())
}

// tagsForAction narrows fallback candidates to the tag kinds the step action
// can operate on. A bare recorded selector keeps the set open.
func tagsForAction(action, selector string) []string {
	switch action {
	case "fill", "input", "type", "press":
		return []string{"input", "textarea", "select", "[contenteditable]"}
	case "click", "doubleclick", "submit":
		return []string{"button", "a", "input", "[role=button]"}
	case "waitvisible":
		return nil
	default:
		return nil
	}
}

var (
	// quotedTokenRE pulls human-readable tokens out of quoted attribute values
	// ("Email address", user-name, aria text) inside CSS/XPath selectors.
	quotedTokenRE = regexp.MustCompile("[\"'`]([^\"'`]+)[\"'`]")
	// identifierTokenRE splits bare selector fragments into id/name-like words:
	// #user-email → user email; input[name=passwd] handled via quoted path.
	identifierTokenRE = regexp.MustCompile(`[A-Za-z][A-Za-z0-9_-]+`)
	selectorStopwords = map[string]struct{}{
		// Structural / selector-grammar words only. Action words such as
		// "submit", "login", "next" are intentionally kept because they are
		// frequently the visible button text the label tier matches against.
		"input": {}, "button": {}, "textarea": {}, "select": {}, "form": {},
		"div": {}, "span": {}, "label": {}, "a": {}, "type": {}, "name": {},
		"id": {}, "class": {}, "xpath": {}, "text": {}, "aria": {}, "html": {},
		"body": {}, "true": {}, "false": {}, "role": {}, "tag": {},
	}
)

// labelKeywords builds the tier-2 search terms: human-readable label hints
// recorded alongside the selector lead (they are the page's actual text),
// followed by words derived from the selector itself.
func (r *stepResolver) labelKeywords(step LoginStep) []string {
	seen := map[string]struct{}{}
	var keywords []string
	add := func(word string) {
		word = strings.ToLower(strings.TrimSpace(word))
		if word == "" {
			return
		}
		if _, dup := seen[word]; dup {
			return
		}
		seen[word] = struct{}{}
		keywords = append(keywords, word)
	}
	for _, hint := range step.LabelHints {
		add(hint)
	}
	for _, word := range selectorKeywords(step.Selector) {
		add(word)
	}
	if len(keywords) > 8 {
		keywords = keywords[:8]
	}
	return keywords
}

// selectorKeywords derives human-readable label keywords from a dead selector.
// Quoted strings and id/name fragments are tokenized into lowercase words so
// "#user-email" and xpath id='login-password' still hint at "email"/"password".
func selectorKeywords(selector string) []string {
	selector = strings.TrimSpace(selector)
	if selector == "" {
		return nil
	}
	seen := map[string]struct{}{}
	var keywords []string
	addToken := func(raw string) {
		for _, word := range strings.FieldsFunc(strings.ToLower(raw), func(r rune) bool {
			return r == '-' || r == '_' || r == '.' || r == '#' || r == '[' || r == ']' ||
				r == '=' || r == '/' || r == ':' || r == '*' || r == '@' || r == ' '
		}) {
			if len(word) < 2 {
				continue
			}
			if _, stop := selectorStopwords[word]; stop {
				continue
			}
			if _, dup := seen[word]; dup {
				continue
			}
			seen[word] = struct{}{}
			keywords = append(keywords, word)
		}
	}

	// Quoted fragments carry the strongest signal (label text, attribute
	// values); evaluate them first so they lead the keyword list.
	for _, match := range quotedTokenRE.FindAllStringSubmatch(selector, -1) {
		addToken(match[1])
	}
	// Then bare identifier fragments, skipping xpath axis/function noise.
	for _, match := range identifierTokenRE.FindAllString(selector, -1) {
		addToken(match)
	}
	if len(keywords) > 8 {
		keywords = keywords[:8]
	}
	return keywords
}
