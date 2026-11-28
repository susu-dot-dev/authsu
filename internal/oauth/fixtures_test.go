//nolint:goconst // table-driven tests repeat case names and inputs on purpose; a constant per row would hide the table
package oauth_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/susu-dot-dev/authsu/internal/apierr"
	"github.com/susu-dot-dev/authsu/internal/auth"
	"github.com/susu-dot-dev/authsu/internal/config"
	"github.com/susu-dot-dev/authsu/internal/httpapi"
	"github.com/susu-dot-dev/authsu/internal/input"
	"github.com/susu-dot-dev/authsu/internal/oauth"
	"github.com/susu-dot-dev/authsu/internal/resource"
	"github.com/susu-dot-dev/authsu/internal/result"
	"github.com/susu-dot-dev/authsu/internal/scope"
	"github.com/susu-dot-dev/authsu/internal/secret"
	"github.com/susu-dot-dev/authsu/internal/store"
)

// *store.Store is what runs in production, so it must satisfy the interface the
// routes are written against.
var _ oauth.Store = (*store.Store)(nil)

// Deployment configuration the tests run under: production's tables (the API
// origin is https).
const (
	testSecret = "oauth-test-secret-0123456789ABCDEFGHIJKLMNOPQRS" //nolint:gosec // a throwaway secret of the tests

	// testSigningKey is a throwaway RSA 2048 private key in the form
	// OAUTH_SIGNING_KEY holds: PKCS#8 DER, base64url without padding, one line.
	testSigningKey = "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC6ahvNJu31g6Bs" +
		"JC2aVJBrcyCubvwgl8wYMHW0yV__jUIzhjaDK4h5HDuUPkJV3pF842ynmC0XIawe" +
		"FiivW6uI-kpesoc2DUWHCoUte81nKEKOjFeu2TvbR7dLZlVt3F4fTsyn2sXfUsHm" +
		"UXiTvuWNV2mQVrfmnaCMihLkGCoCNP7wJ2jAkeTAbgcL61foSxhAdygXDIgLUxzR" +
		"47N0nv4G02Z0eWIFPb8rar3ppSt3UX1Cl569iFb6wk3_7QVYNCodhjYm5IPioW6B" +
		"FJsts6-FbGkC_7RIATwNeGiJezxb_ClO_6ZxEMeVcadhy0FWL8wp4iO15zELJ1o-" +
		"tX0i-FmBAgMBAAECggEABIJBFVHITV2ghNiET5GVMTr9WahzRUjUWlhIktW1Nv7d" +
		"9VWmR1FZqosZ_KrJaRpKLNn8fsysCoad-NfAXU-7cvptGO1D8RmaOFaFX9MdnLtr" +
		"adc9cNU3INfKE7w5VwkzL-M9v_q-FVVMPZuYknEfAx1P2p8HeokOoQ5xUfVRYRVj" +
		"VfpBBrJbbqUvqN_q8VQImWZTNkmcE1Y1LE0XZIevj9im9ZjwbDnwhPv3ST0jmPoH" +
		"K97oxEAF36bT71uNeizgcPCtJaV6L3HXayNIo-IxFMtjOW9wcXHtTQDSh8FEsx_G" +
		"aVYNqdbwCL3FtDFauA3GBNTDw6HBBXXxo-4VDFQHoQKBgQDN5bFE2YVPdlWb1kMj" +
		"C3zGrZrFZ59n-hoPxU9iaM-8oobPsTy7Zr9UzSSawhfIPOHTJr69SQfiIV23iBJo" +
		"6k_X1BKAti1oFZ0_Ir-oiskMyH39LEyFoR4OxzzCtCxz03MOY0CQYofF3tCF-Glp" +
		"bz1d6r06J5Xjw7atNaC-AJJjfwKBgQDnxr536dM0907Fl-rGGm70CqL6Nh9oiwpF" +
		"rSjaeWi2HcIrQX_4ScNqugUIShc4KIwQhBIWSS9Fd4ydOKD7eyuDLoI6yXBx8Ft8" +
		"dAs_Xir8ya7s_23Za_7hZ2PGaLhgdtUVwgzzvm0z9_PihlPOoXgAj1ooPvvVEMon" +
		"SbnHmr_C_wKBgGFR_V0-t51coJBdUTSCXIMIUcyW8yjRdXoY2DH6up498BzBeKRX" +
		"p34szO19aoJSDKeie6u6lkhTXxm97n26quyoJ-rAsWuuM7pA8Xh3yRoKtkpxouXS" +
		"xwNTNywMv6oruwmE7mKQv_5OGCAKz8BvPQFkT_bp-RZETtdGLulAGfF_AoGBAJMT" +
		"T7wiGY9Lu6WxQB6TmYKs2TyzaXzadhs-xWTVk_e0rIjsWHtCu4mXHyhic5eES1UT" +
		"qbKQoDmRoh4GWEkcoMDum18Ygo0au8MelCCS7e5ZQPJNJ_THDgcUp4C45P75iT_0" +
		"Umm9lehbWFyPZtEBL3gTf194kC9lJxKFOymJblQbAoGAZYVraT4JOj1G400k9UFw" +
		"1lJRMpjKZ8NWMOLNHIE60GRAxm49exY0hVip4gOrHOZjLqxor6sdU5OS_G3O1UE0" +
		"dEqAmP3FiJcYqf-8W9qUPc1KulMqnuGndE6ZFpXHlVkhRwWD1ZebATTXh9EzmuDS" +
		"SVOw37zoh_COkszjZ24btDs"

	apiOrigin = "https://auth.example.com"
	uiOrigin  = "https://ui.example.com"

	// The client under test: its metadata document's URL, and the redirect URIs
	// the document registers.
	clientURL    = "https://client.example.com/oauth/client.json"
	clientHost   = "client.example.com"
	redirectURL  = "https://client.example.com/callback"
	loopbackURL  = "http://127.0.0.1/cb"
	localhostURL = "http://localhost/cb"
	clientName   = "Example Client"
	resourceURL  = resource.ProductionURL
	challengeVal = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"

	userA   = "00000000-0000-7000-8000-00000000000a"
	userB   = "00000000-0000-7000-8000-00000000000b"
	agentA1 = "00000000-0000-7000-8000-0000000000c1"
	agentB1 = "00000000-0000-7000-8000-0000000000c2"
	nobody  = "00000000-0000-7000-8000-0000000000ee"

	// grantID and newAgentID are the ids NewID hands out first and second.
	grantID    = "00000000-0000-7000-8000-0000000000d1"
	newAgentID = "00000000-0000-7000-8000-0000000000d2"

	roleMember = "member"

	jsonType = "application/json"
	noStore  = "no-store"
)

// Causes the tests inject. They are only ever in the log, never in a response.
var (
	errDB      = errors.New("INSERT INTO oauth_grants: database is on fire")
	errEntropy = errors.New("the entropy source is broken")
	errNet     = errors.New("dial tcp: connection refused")
)

// fullEnv is a complete, valid deployment configuration.
func fullEnv() map[string]string {
	return map[string]string{
		config.SecretHMAC:            testSecret,
		config.SecretOAuthSigningKey: testSigningKey,
		config.VarAPIOrigin:          apiOrigin,
		config.VarUIOrigin:           uiOrigin,
	}
}

// devEnv is the development deployment: an http://localhost API, which selects
// the development table and admits localhost clients.
func devEnv() map[string]string {
	env := fullEnv()
	env[config.VarAPIOrigin] = "http://localhost:8787"
	env[config.VarUIOrigin] = "http://localhost:3000"

	return env
}

// storeCall is one call to the fake store: the operation, the clock it was
// given, and the arguments of the operation it was.
type storeCall struct {
	op  string
	now time.Time

	grant    store.NewGrant
	exchange store.CodeExchange
	refresh  store.RefreshExchange
	token    string
	client   input.ClientID
	resource input.ResourceID
	owner    string
	id       input.ID
	cursor   input.Cursor
	limit    input.PageLimit
}

// The operations a storeCall can be.
const (
	opCreateGrant = "CreateGrant"
	opExchange    = "ExchangeCode"
	opRefresh     = "Refresh"
	opIntrospect  = "IntrospectAccessToken"
	opRevokeRT    = "RevokeRefreshToken"
	opRevokeAT    = "RevokeAccessToken"
	opList        = "ListGrants"
	opGet         = "GetGrant"
	opRevokeGrant = "RevokeGrant"
)

// grantRow is a grant as the fake keeps it: what consent wrote, and what the
// exchanges and the revocations did to it since. It models the rules the real
// writes carry (store.rotateCodeQuery and the others), so a flow through the
// routes behaves as one through the database would.
type grantRow struct {
	grant    store.NewGrant
	authTime time.Time

	// rotated is whether the code was exchanged: the grant's secret then holds
	// a refresh token, and the grant has an access token.
	rotated        bool
	refreshHash    []byte
	refreshExpires time.Time

	accessID      string
	accessHash    []byte
	accessScope   string
	accessIssued  time.Time
	accessExpires time.Time
	accessRevoked bool

	revokedAt *time.Time
}

// expires is when the grant's secret stops being active: the retention of the
// code-stage row, then the latest refresh token's. The code's own minute is not
// the secret's expiry (see young).
func (g *grantRow) expires() time.Time {
	if g.rotated {
		return g.refreshExpires
	}

	return g.grant.RetainUntil
}

// young reports whether the code is younger than lifetime at now, judged from
// the consent as the exchange write judges it from the secret's creation: the
// code is good while now is before consent plus its life.
func (g *grantRow) young(lifetime time.Duration, now time.Time) bool {
	return g.grant.CreatedAt.Add(lifetime).After(now)
}

// alive reports whether the grant's secret is active at now.
func (g *grantRow) alive(now time.Time) bool {
	return (g.revokedAt == nil || g.revokedAt.After(now)) && g.expires().After(now)
}

// fakeStore is the grant store: it applies the refusals of store.CreateGrant in
// the order the real write reports them, models the exchanges, introspection
// and revocations of the real writes, records every call, and can be programmed
// to fail. A grant is the single use of its sealed request, so a second call
// with the same granted_from is a replay.
type fakeStore struct {
	// failure, when set, is returned by every operation before anything is
	// written.
	failure error

	// inactiveUsers, endedSessions, agents, revokedAgents and agentNames are the
	// facts the writes check: a revoked account, a session that was ended, the
	// agents that exist (an agent is the user's and active, or is not there),
	// the ones that were revoked since, and their names.
	inactiveUsers map[string]bool
	endedSessions map[string]bool
	agents        map[string]string
	activeAgents  map[string]int
	revokedAgents map[string]bool
	agentNames    map[string]string

	// firstPartyAgents is the agent authsu keeps for an owner and a client, by
	// "owner|client": what agents.first_party_client holds.
	firstPartyAgents map[string]string

	// agentScopes is agents.scopes by agent id, as a list: what the write sets for
	// an agent authsu creates for a grant (setAgentScopes) and never for one the
	// user attached. A missing agent holds none.
	agentScopes map[string][]string

	// profiles is users.profile by user id, which an exchange reports.
	profiles map[string]string

	// authTimes is when each session was created: a grant's auth_time.
	authTimes map[string]time.Time

	// edit, when set, changes what an exchange or a refresh reports of the
	// grant, after it was rotated: it is how a test hands the routes a grant row
	// the store would never have written.
	edit func(*store.Exchanged)

	calls  []storeCall
	grants []store.NewGrant
	used   map[string]bool
	rows   []*grantRow
}

func newFakeStore() *fakeStore {
	return &fakeStore{
		inactiveUsers: map[string]bool{}, endedSessions: map[string]bool{},
		agents:        map[string]string{agentA1: userA, agentB1: userB},
		activeAgents:  map[string]int{userA: 1, userB: 1},
		revokedAgents: map[string]bool{},
		agentNames:    map[string]string{agentA1: "Agent A1", agentB1: "Agent B1"},
		authTimes:     map[string]time.Time{},
		used:          map[string]bool{},

		firstPartyAgents: map[string]string{},
		agentScopes:      map[string][]string{},
		profiles:         map[string]string{userA: `{"name":"Alice A","email":"alice@example.com"}`},
	}
}

// CreateGrant is the contract of store.CreateGrant.
func (f *fakeStore) CreateGrant(_ context.Context, grant store.NewGrant) error {
	f.calls = append(f.calls, storeCall{op: opCreateGrant, grant: grant, now: grant.CreatedAt})

	err := f.refuse(grant)
	if err != nil {
		return err
	}

	f.used[hex.EncodeToString(grant.GrantedFrom)] = true
	f.grants = append(f.grants, grant)

	authTime, known := f.authTimes[grant.SessionID]
	if !known {
		authTime = grant.CreatedAt
	}

	f.rows = append(f.rows, &grantRow{grant: grant, authTime: authTime})

	if grant.NewAgent != nil {
		f.agents[grant.AgentID] = grant.Owner
		f.agentNames[grant.AgentID] = grant.NewAgent.Name.String()
		f.activeAgents[grant.Owner]++
		f.agentScopes[grant.AgentID] = f.unionScopes(nil, grant)
	}

	if grant.FirstParty {
		f.holdFirstParty(grant)
	}

	return nil
}

// ExchangeCode is the contract of store.ExchangeCode: a code is spent once, for
// the client and the redirect URI it was approved for and the challenge of the
// verifier, while it is younger than its life, and it, its account and its agent
// are active. A resource it names must be the grant's, and is judged only for a
// code that is otherwise good, as the real write's diagnosis does.
func (f *fakeStore) ExchangeCode(
	_ context.Context, exchange store.CodeExchange, now time.Time,
) (store.Exchanged, error) {
	f.calls = append(f.calls, storeCall{op: opExchange, exchange: exchange, now: now})

	if f.failure != nil {
		return store.Exchanged{}, f.failure
	}

	for _, g := range f.rows {
		if !f.goodCode(g, exchange, now) {
			continue
		}

		if exchange.Resource != nil && exchange.Resource.String() != g.grant.Resource.String() {
			return store.Exchanged{}, store.ErrInvalidTarget
		}

		rotate(g, exchange.Tokens, g.grant.Scope.String(), now)
		f.supersede(g, now)

		return f.exchanged(g), nil
	}

	return store.Exchanged{}, store.ErrInvalidGrant
}

// Refresh is the contract of store.Refresh: the scope asked for must be within
// the grant's and the resource its own, for a token that is otherwise live and the
// client's, and nothing is rotated when either is not.
func (f *fakeStore) Refresh(_ context.Context, exchange store.RefreshExchange, now time.Time) (store.Exchanged, error) {
	f.calls = append(f.calls, storeCall{op: opRefresh, refresh: exchange, now: now})

	if f.failure != nil {
		return store.Exchanged{}, f.failure
	}

	for _, g := range f.rows {
		matches := g.rotated && bytes.Equal(g.refreshHash, exchange.Token.Hash()) && g.alive(now) &&
			g.grant.ClientID == exchange.ClientID && f.usable(g)
		if !matches {
			continue
		}

		scope, err := refreshedScope(g, exchange)
		if err != nil {
			return store.Exchanged{}, err
		}

		rotate(g, exchange.Tokens, scope, now)

		return f.exchanged(g), nil
	}

	return store.Exchanged{}, store.ErrInvalidGrant
}

// refreshedScope is the scope a refresh of the grant issues, or the refusal: the
// resource first, then the scope, as the real diagnosis reports them.
func refreshedScope(g *grantRow, exchange store.RefreshExchange) (string, error) {
	switch {
	case exchange.Resource != nil && exchange.Resource.String() != g.grant.Resource.String():
		return "", store.ErrInvalidTarget
	case exchange.Scope != nil && !within(exchange.Scope.Names(), g.grant.Scope.Names()):
		return "", store.ErrInvalidScope
	case exchange.Scope != nil:
		return exchange.Scope.String(), nil
	default:
		return g.grant.Scope.String(), nil
	}
}

// IntrospectAccessToken is the contract of store.IntrospectAccessToken.
func (f *fakeStore) IntrospectAccessToken(
	_ context.Context, token input.AccessToken, target input.ResourceID, now time.Time,
) (store.ActiveAccessToken, bool, error) {
	f.calls = append(f.calls, storeCall{op: opIntrospect, token: token.String(), resource: target, now: now})

	if f.failure != nil {
		return store.ActiveAccessToken{}, false, f.failure
	}

	for _, g := range f.rows {
		live := g.rotated && bytes.Equal(g.accessHash, token.Hash()) && !g.accessRevoked && g.accessExpires.After(now) &&
			g.alive(now) && f.usable(g) && g.grant.Resource.String() == target.String()
		if live {
			return store.ActiveAccessToken{
				UserID: g.grant.Owner, AgentID: g.grant.AgentID, ClientID: g.grant.ClientID.String(),
				Resource: g.grant.Resource.String(), Scope: g.accessScope, IssuedAt: g.accessIssued,
				ExpiresAt: g.accessExpires,
			}, true, nil
		}
	}

	return store.ActiveAccessToken{}, false, nil
}

// RevokeRefreshToken is the contract of store.RevokeRefreshToken.
func (f *fakeStore) RevokeRefreshToken(
	_ context.Context, token input.RefreshToken, client input.ClientID, now time.Time,
) error {
	f.calls = append(f.calls, storeCall{op: opRevokeRT, token: token.String(), client: client, now: now})

	if f.failure != nil {
		return f.failure
	}

	for _, g := range f.rows {
		if g.rotated && bytes.Equal(g.refreshHash, token.Hash()) && g.grant.ClientID == client &&
			(g.revokedAt == nil || g.revokedAt.After(now)) {
			g.revokedAt = &now
			g.accessRevoked = true
		}
	}

	return nil
}

// RevokeAccessToken is the contract of store.RevokeAccessToken.
func (f *fakeStore) RevokeAccessToken(
	_ context.Context, token input.AccessToken, client input.ClientID, now time.Time,
) error {
	f.calls = append(f.calls, storeCall{op: opRevokeAT, token: token.String(), client: client, now: now})

	if f.failure != nil {
		return f.failure
	}

	for _, g := range f.rows {
		if g.rotated && bytes.Equal(g.accessHash, token.Hash()) && g.grant.ClientID == client {
			g.accessRevoked = true
		}
	}

	return nil
}

// ListGrants is the contract of store.ListGrants.
func (f *fakeStore) ListGrants(
	_ context.Context, owner string, cursor input.Cursor, limit input.PageLimit,
) (store.GrantPage, error) {
	f.calls = append(f.calls, storeCall{op: opList, owner: owner, cursor: cursor, limit: limit})

	if f.failure != nil {
		return store.GrantPage{}, f.failure
	}

	var page store.GrantPage

	before, bounded := cursor.ID()

	for _, g := range f.owned(owner) {
		if bounded && g.grant.ID >= before.String() {
			continue
		}

		if len(page.Grants) == max(limit.Int(), 1) {
			page.Next = page.Grants[len(page.Grants)-1].ID

			break
		}

		page.Grants = append(page.Grants, f.view(g))
	}

	return page, nil
}

// GetGrant is the contract of store.GetGrant.
func (f *fakeStore) GetGrant(_ context.Context, owner string, id input.ID) (store.Grant, error) {
	f.calls = append(f.calls, storeCall{op: opGet, owner: owner, id: id})

	if f.failure != nil {
		return store.Grant{}, f.failure
	}

	for _, g := range f.owned(owner) {
		if g.grant.ID == id.String() {
			return f.view(g), nil
		}
	}

	return store.Grant{}, store.ErrNotFound
}

// RevokeGrant is the contract of store.RevokeGrant.
func (f *fakeStore) RevokeGrant(_ context.Context, owner string, id input.ID, now time.Time) (store.Grant, error) {
	f.calls = append(f.calls, storeCall{op: opRevokeGrant, owner: owner, id: id, now: now})

	if f.failure != nil {
		return store.Grant{}, f.failure
	}

	for _, g := range f.owned(owner) {
		if g.grant.ID == id.String() {
			if g.revokedAt == nil || g.revokedAt.After(now) {
				g.revokedAt = &now
				g.accessRevoked = true
			}

			return f.view(g), nil
		}
	}

	return store.Grant{}, store.ErrNotFound
}

// supersede is the revocation an exchange makes of the older grants of the same
// user, client and resource (store.supersedeGrantQuery): those consented before the
// exchanged grant, by id, which is a UUIDv7. A revocation already due keeps its
// time.
func (f *fakeStore) supersede(exchanged *grantRow, now time.Time) {
	for _, g := range f.rows {
		older := g.grant.Owner == exchanged.grant.Owner && g.grant.ClientID == exchanged.grant.ClientID &&
			g.grant.Resource.String() == exchanged.grant.Resource.String() && g.grant.ID < exchanged.grant.ID
		if !older {
			continue
		}

		if g.revokedAt == nil || g.revokedAt.After(now) {
			g.revokedAt = &now
		}

		if g.rotated {
			g.accessRevoked = true
		}
	}
}

// holdFirstParty is the effect of a first-party login's write: the owner's active
// agent for the client is found, or one is created under the grant's agent id (a
// revoked one is not found, and no longer counts against the limit), and holds
// the grant.
func (f *fakeStore) holdFirstParty(grant store.NewGrant) {
	key := grant.Owner + "|" + grant.ClientID.String()

	agent, found := f.firstPartyAgents[key]
	if found && f.revokedAgents[agent] {
		found = false
		f.activeAgents[grant.Owner]--
	}

	if !found {
		agent = grant.AgentID
		f.firstPartyAgents[key] = agent
		f.agents[agent] = grant.Owner
		f.agentNames[agent] = grant.FirstPartyName.String()
		f.agentScopes[agent] = []string{}
		f.activeAgents[grant.Owner]++
	}

	// The list is set in the same write, to the union of what the agent holds and
	// what the grant asks for, kept to the allowlist (store.grantFirstPartyScopesQuery).
	f.agentScopes[agent] = f.unionScopes(f.agentScopes[agent], grant)

	f.rows[len(f.rows)-1].grant.AgentID = agent
}

// unionScopes is the list an agent authsu writes for a grant ends up with: the
// allowlist's names, in its order, that the agent holds or the grant asks for.
// Written as plain Go, apart from the SQL it models, so a test of either checks
// the other.
func (f *fakeStore) unionScopes(held []string, grant store.NewGrant) []string {
	out := []string{}

	for _, name := range grant.Allowlist {
		if slices.Contains(held, name) || slices.Contains(grant.Scope.Names(), name) {
			out = append(out, name)
		}
	}

	return out
}

// goodCode reports whether the grant is the exchange's, in everything but the
// resource.
func (f *fakeStore) goodCode(g *grantRow, exchange store.CodeExchange, now time.Time) bool {
	return !g.rotated && bytes.Equal(g.grant.CodeHash, exchange.Code.Hash()) && g.alive(now) &&
		g.young(exchange.CodeLifetime, now) &&
		g.grant.ClientID == exchange.ClientID && g.grant.RedirectURI == exchange.RedirectURI &&
		g.grant.CodeChallenge == exchange.Verifier.Challenge() && f.usable(g)
}

// within reports whether every name asked for is one of the grant's, as the
// rotation of the real write compares them (store.rotateRefreshQuery).
func within(asked, granted []string) bool {
	return !slices.ContainsFunc(asked, func(name string) bool { return !slices.Contains(granted, name) })
}

// usable reports whether the grant's account and agent are active.
func (f *fakeStore) usable(g *grantRow) bool {
	return !f.inactiveUsers[g.grant.Owner] && !f.revokedAgents[g.grant.AgentID]
}

// exchanged is the grant as a rotation reports it.
func (f *fakeStore) exchanged(g *grantRow) store.Exchanged {
	out := store.Exchanged{
		UserID: g.grant.Owner, AgentID: g.grant.AgentID, ClientID: g.grant.ClientID.String(),
		Resource: g.grant.Resource.String(), Scope: g.accessScope, AuthTime: g.authTime,
		Profile: f.profiles[g.grant.Owner],
	}

	if g.grant.Nonce != nil {
		nonce := g.grant.Nonce.String()
		out.Nonce = &nonce
	}

	if f.edit != nil {
		f.edit(&out)
	}

	return out
}

// rotate gives the grant the tokens, as the real rotation does, and the access
// token the scope.
func rotate(g *grantRow, tokens store.NewTokens, scope string, now time.Time) {
	g.rotated = true
	g.accessScope = scope
	g.refreshHash = tokens.RefreshHash
	g.refreshExpires = tokens.RefreshExpiresAt

	if g.accessID == "" {
		g.accessID = tokens.AccessID
	}

	g.accessHash = tokens.AccessHash
	g.accessIssued = now
	g.accessExpires = tokens.AccessExpiresAt
	g.accessRevoked = false
}

// view is the grant as the store lists it.
func (f *fakeStore) view(g *grantRow) store.Grant {
	out := store.Grant{
		ID: g.grant.ID, AgentID: g.grant.AgentID, AgentName: f.agentNames[g.grant.AgentID],
		ClientID: g.grant.ClientID.String(), ClientName: g.grant.ClientName, Resource: g.grant.Resource.String(),
		Scope: g.grant.Scope.String(), ExpiresAt: g.expires().Unix(), CreatedAt: g.grant.CreatedAt.Unix(),
	}

	if g.revokedAt != nil {
		revoked := g.revokedAt.Unix()
		out.RevokedAt = &revoked
	}

	return out
}

// owned is the owner's grants, exchanged or not, newest first (their ids are
// UUIDv7s).
func (f *fakeStore) owned(owner string) []*grantRow {
	var out []*grantRow

	for _, g := range f.rows {
		if g.grant.Owner == owner {
			out = append(out, g)
		}
	}

	slices.SortFunc(out, func(a, b *grantRow) int { return strings.Compare(b.grant.ID, a.grant.ID) })

	return out
}

// refuse is the refusal of store.CreateGrant, if there is one, in the order the real
// write reports them.
func (f *fakeStore) refuse(grant store.NewGrant) error {
	agent := f.refuseAgent(grant)

	switch {
	case f.failure != nil:
		return f.failure
	case f.inactiveUsers[grant.Owner]:
		return fmt.Errorf("%w: %w", store.ErrUserInactive, store.ErrConflict)
	case agent != nil:
		return fmt.Errorf("%w: %w", agent, store.ErrConflict)
	case f.endedSessions[grant.SessionID]:
		return fmt.Errorf("%w: %w", store.ErrSessionInactive, store.ErrConflict)
	case f.used[hex.EncodeToString(grant.GrantedFrom)]:
		return fmt.Errorf("%w: %w", store.ErrGrantReplayed, store.ErrConflict)
	default:
		return nil
	}
}

// refuseAgent is the refusal of the grant's agent: the owner is at the limit, for
// an agent the grant creates, and the agent is not an active agent of the owner,
// for one it names.
func (f *fakeStore) refuseAgent(grant store.NewGrant) error {
	switch {
	case grant.NewAgent != nil && f.activeAgents[grant.Owner] >= grant.NewAgent.MaxActive:
		return store.ErrAgentLimit
	case grant.FirstParty:
		return f.refuseFirstParty(grant)
	case grant.NewAgent == nil && (f.agents[grant.AgentID] != grant.Owner || f.revokedAgents[grant.AgentID]):
		return store.ErrAgentUnavailable
	default:
		return nil
	}
}

// refuseFirstParty is the refusal of a first-party login's agent: an active one
// that exists is used and is not held to the limit; one that is not there, or is
// revoked, is created, which the limit refuses when the owner is at it (a revoked
// one no longer counts against it).
func (f *fakeStore) refuseFirstParty(grant store.NewGrant) error {
	agent, found := f.firstPartyAgents[grant.Owner+"|"+grant.ClientID.String()]
	active := found && !f.revokedAgents[agent]

	used := f.activeAgents[grant.Owner]
	if found && !active {
		used--
	}

	if !active && used >= grant.FirstPartyMaxActive {
		return store.ErrAgentLimit
	}

	return nil
}

// fetchAnswer is what the fake network answers for a URL.
type fetchAnswer struct {
	status      int
	contentType string
	body        string
	location    string
	err         error
}

// fakeFetch is the outbound fetch: it answers each URL from a table, and
// records every request it was asked to send.
type fakeFetch struct {
	answers map[string]fetchAnswer

	// Requests are sent from the handler's goroutine but tests read the record
	// while concurrent requests are in flight, so the record is guarded.
	mu       sync.Mutex
	requests []*http.Request
}

// sent returns the requests the fetch was asked to send so far.
func (f *fakeFetch) sent() []*http.Request {
	f.mu.Lock()
	defer f.mu.Unlock()

	return slices.Clone(f.requests)
}

// do is the fetch.Doer.
func (f *fakeFetch) do(req *http.Request) (*http.Response, error) {
	f.mu.Lock()
	f.requests = append(f.requests, req)
	f.mu.Unlock()

	// The platform's fetch ends with the request's context, which is what a
	// caller that went away has done to it.
	err := req.Context().Err()
	if err != nil {
		return nil, err //nolint:wrapcheck // the platform's fetch fails with the context's own error
	}

	answer, found := f.answers[req.URL.String()]
	if !found {
		answer = fetchAnswer{status: http.StatusNotFound, contentType: "text/html", body: "not found"}
	}

	if answer.err != nil {
		return nil, answer.err
	}

	header := http.Header{}
	if answer.contentType != "" {
		header.Set("Content-Type", answer.contentType)
	}

	if answer.location != "" {
		header.Set("Location", answer.location)
	}

	return &http.Response{
		StatusCode: answer.status, Header: header, Body: io.NopCloser(strings.NewReader(answer.body)),
		ContentLength: int64(len(answer.body)),
	}, nil
}

// document is a client metadata document for clientID that registers uris.
func document(clientID string, uris ...string) string {
	body, err := json.Marshal(map[string]any{
		"client_id": clientID, "client_name": clientName, "redirect_uris": uris,
	})
	if err != nil {
		panic(err)
	}

	return string(body)
}

// served is the answer of a server that publishes body as JSON.
func served(body string) fetchAnswer {
	return fetchAnswer{status: http.StatusOK, contentType: jsonType, body: body}
}

// fakeCredentials is the credential store the boundary resolves tokens with.
type fakeCredentials struct {
	sessions map[string]store.ActiveSession
	keys     map[string]store.ActiveAPIKey

	// grants is the fake grant store, whose rows and agent lists an access token
	// resolves against.
	grants *fakeStore
}

// ResolveSession answers for an active session.
func (f *fakeCredentials) ResolveSession(
	_ context.Context, token input.SessionToken, _ time.Time,
) (store.ActiveSession, bool, error) {
	row, found := f.sessions[string(token.Hash())]

	return row, found, nil
}

// ResolveAPIKey answers for an active API key.
func (f *fakeCredentials) ResolveAPIKey(
	_ context.Context, token input.APIKeyToken, _ time.Time,
) (store.ActiveAPIKey, bool, error) {
	row, found := f.keys[string(token.Hash())]

	return row, found, nil
}

// ResolveGrant is the contract of store.ResolveGrant over the fake store: a live
// access token of a grant for exactly the login resource found by its hash, with
// the account, the agent and the agent's list as the consent left them, read now.
// An access token of another resource, of a revoked agent or of an agent no longer
// the user's is not found.
func (f *fakeCredentials) ResolveGrant(
	_ context.Context, token input.AccessToken, login input.ResourceID, now time.Time,
) (store.ActiveGrant, bool, error) {
	for _, g := range f.grants.rows {
		live := g.rotated && bytes.Equal(g.accessHash, token.Hash()) && !g.accessRevoked &&
			g.accessExpires.After(now) && g.alive(now) && f.grants.usable(g) &&
			g.grant.Resource.String() == login.String()
		if !live {
			continue
		}

		stored, err := json.Marshal(f.grants.agentScopes[g.grant.AgentID])
		if err != nil {
			panic(err)
		}

		return store.ActiveGrant{
			ID: g.accessID, UserID: g.grant.Owner, Role: roleMember, ExpiresAt: g.accessExpires, OrgID: "org-1",
			AgentID: g.grant.AgentID, AgentScopes: string(stored), Scope: g.accessScope,
		}, true, nil
	}

	return store.ActiveGrant{}, false, nil
}

// grantProbeRoutes are routes of authsu's own API as a feature declares them,
// stood in for here: each opts in to grants with FromGrants and needs one scope,
// and answers 204 when the boundary lets the request through. They are the real
// boundary's view of an access token a login was issued (internal/auth), so a
// test of the consent can follow its agent's list all the way to a permission.
func grantProbeRoutes() []auth.Route {
	probe := func(path string, access auth.Access) auth.Route {
		return auth.Route{
			Method: http.MethodGet, Path: path, Credential: auth.Authenticated, Access: access,
			Handle: func(*auth.Call) result.Result[httpapi.Response] {
				return result.Ok(httpapi.Response{Status: http.StatusNoContent})
			},
		}
	}

	return []auth.Route{
		probe("/probe/"+string(scope.SandboxCreate), auth.Needs(scope.SandboxCreate).FromGrants()),
		probe("/probe/"+string(scope.SandboxRevoke), auth.Needs(scope.SandboxRevoke).FromGrants()),
		probe("/probe/"+string(scope.OrgRead), auth.Needs(scope.OrgRead).FromGrants()),
		probe("/probe/"+string(scope.AgentCreate), auth.Needs(scope.AgentCreate).FromGrants()),
		probe("/probe/"+string(scope.AgentRead), auth.Needs(scope.AgentRead).FromGrants()),
	}
}

// sequence is a deterministic source of entropy: each read returns bytes that
// differ from every other read's.
type sequence struct{ reads uint64 }

func (s *sequence) Read(p []byte) (int, error) {
	s.reads++

	sum := sha256.Sum256(binary.BigEndian.AppendUint64(nil, s.reads))

	return copy(p, sum[:]), nil
}

// brokenReader is an entropy source that always fails.
type brokenReader struct{}

func (brokenReader) Read([]byte) (int, error) { return 0, errEntropy }

// readerFunc is an io.Reader made of a function.
type readerFunc func([]byte) (int, error)

func (f readerFunc) Read(p []byte) (int, error) { return f(p) }

// rig is one deployment under test: the real boundary and the real OAuth routes
// over a fake store, a fake network, a fake credential store and a clock the
// test controls.
type rig struct {
	t     *testing.T
	store *fakeStore
	net   *fakeFetch
	creds *fakeCredentials
	env   map[string]string

	now time.Time
	// entropy is what the routes read from; signer is the separate source the
	// rig's own sign-ins use.
	entropy io.Reader
	signer  *sequence
	// ids are the ids NewID hands out, then distinct ones.
	ids     []string
	handed  int
	signs   int
	maxAges int

	// tables, when set, selects the resource table for each lookup in the order the
	// routes make them, so a test can hand the routes a table that changes between
	// the steps of one request. It is nil for the deployment's own table.
	tables func(call int, apiOrigin string) resource.Table
	looked int

	// logged records every error the boundary turned into a response and every
	// redirect the routes logged.
	logged  []*apierr.Error
	handler http.Handler
}

func newRig(t *testing.T) *rig {
	t.Helper()

	return newRigWith(t, fullEnv())
}

func newRigWith(t *testing.T, env map[string]string) *rig {
	t.Helper()

	rg := &rig{
		t: t, store: newFakeStore(), env: env,
		net:   &fakeFetch{answers: map[string]fetchAnswer{}},
		creds: nil,
		// A fixed instant, in whole seconds: the payload carries Unix seconds.
		now:     time.Date(2030, time.March, 4, 5, 6, 7, 0, time.UTC),
		entropy: &sequence{reads: 1 << 32},
		signer:  &sequence{reads: 0},
		ids:     []string{grantID, newAgentID},
		maxAges: 25,
	}

	rg.net.answers[clientURL] = served(document(clientURL, redirectURL, loopbackURL, localhostURL))

	rg.creds = &fakeCredentials{
		sessions: map[string]store.ActiveSession{}, keys: map[string]store.ActiveAPIKey{}, grants: rg.store,
	}

	rg.handler = auth.Handler(append(oauth.Routes(rg.deps()), grantProbeRoutes()...), auth.Deps{
		Credentials: rg.creds,
		Resources:   resource.Select,
		Now:         func() time.Time { return rg.now },
		Getenv:      func(name string) string { return rg.env[name] },
		Log:         rg.log,
	})

	return rg
}

// log records a failure.
func (r *rig) log(_ httpapi.Request, failure *apierr.Error) { r.logged = append(r.logged, failure) }

// newID is the routes' id source.
func (r *rig) newID() string {
	r.handed++

	if r.handed <= len(r.ids) {
		return r.ids[r.handed-1]
	}

	return fmt.Sprintf("00000000-0000-7000-8000-%012x", 0x2000+r.handed)
}

// deps are the OAuth routes' dependencies, over the rig's fakes. The entropy is
// read through the rig, so a test may replace it before a request.
func (r *rig) deps() oauth.Deps {
	return oauth.Deps{
		Store: r.store, Resources: r.selectTable, Fetch: r.net.do,
		Now:       func() time.Time { return r.now },
		Entropy:   readerFunc(func(p []byte) (int, error) { return r.entropy.Read(p) }),
		NewID:     r.newID,
		MaxAgents: r.maxAges,
		Log:       r.log,
	}
}

// selectTable is the routes' resource table: the deployment's, or the rig's
// tables hook when a test set one.
func (r *rig) selectTable(apiOrigin string) resource.Table {
	if r.tables == nil {
		return resource.Select(apiOrigin)
	}

	r.looked++

	return r.tables(r.looked, apiOrigin)
}

// config is the deployment's configuration, as the routes load it.
func (r *rig) config() config.Config {
	r.t.Helper()

	cfg, err := config.Load(func(name string) string { return r.env[name] })
	if err != nil {
		r.t.Fatalf("config.Load: %v", err)
	}

	return cfg
}

// signID is an id for the rig's own sign-ins, apart from the routes' ids.
func (r *rig) signID() string {
	r.signs++

	return fmt.Sprintf("00000000-0000-7000-8000-%012x", 0x5000+r.signs)
}

// signIn issues a session for owner, stores it as active and returns the cookie
// a browser would send and the session's secret id.
func (r *rig) signIn(owner string) (*http.Cookie, string) {
	r.t.Helper()

	issued, err := auth.IssueSession(r.signer, r.signID, r.now)
	if err != nil {
		r.t.Fatalf("IssueSession: %v", err)
	}

	r.creds.sessions[string(issued.Hash)] = store.ActiveSession{
		ID: issued.ID, UserID: owner, Role: roleMember, ExpiresAt: issued.ExpiresAt,
	}
	r.store.authTimes[issued.ID] = r.now

	//nolint:gosec // a request cookie carries no attributes; G124 is about Set-Cookie
	return &http.Cookie{Name: auth.CookieName, Value: issued.Token}, issued.ID
}

// signInKey issues an API key for owner (an agent's when agent is set), stores it
// as active, and returns the Authorization header value.
func (r *rig) signInKey(owner, agent string) string {
	r.t.Helper()

	issued, err := auth.IssueUserAPIKey(r.signer, r.signID, r.now, time.Hour)
	if err != nil {
		r.t.Fatalf("IssueUserAPIKey: %v", err)
	}

	r.creds.keys[string(issued.Hash)] = store.ActiveAPIKey{
		ID: issued.ID, UserID: owner, Role: roleMember, ExpiresAt: issued.ExpiresAt, AgentID: agent,
		AgentScopes: `["default:agent"]`, Scope: `["default:user"]`,
	}

	return "Bearer " + issued.Token
}

// request is one request to send.
type request struct {
	method, target, body string
	// contentType defaults to application/json; "-" sends none.
	contentType   string
	cookies       []*http.Cookie
	authorization string
	ctx           context.Context //nolint:containedctx // a test request value carries the context it is sent with
}

// serve sends req and returns the response.
func (r *rig) serve(req request) *httptest.ResponseRecorder {
	r.t.Helper()

	ctx := req.ctx
	if ctx == nil {
		ctx = r.t.Context()
	}

	var reader io.Reader
	if req.body != "" {
		reader = strings.NewReader(req.body)
	}

	httpReq := httptest.NewRequestWithContext(ctx, req.method, req.target, reader)

	switch req.contentType {
	case "":
		httpReq.Header.Set("Content-Type", jsonType)
	case "-":
	default:
		httpReq.Header.Set("Content-Type", req.contentType)
	}

	for _, cookie := range req.cookies {
		httpReq.AddCookie(cookie)
	}

	if req.authorization != "" {
		httpReq.Header.Set("Authorization", req.authorization)
	}

	rec := httptest.NewRecorder()
	r.handler.ServeHTTP(rec, httpReq)

	return rec
}

// get sends a GET of target.
func (r *rig) get(target string) *httptest.ResponseRecorder {
	r.t.Helper()

	return r.serve(request{method: http.MethodGet, target: target})
}

// authorizeParams are the parameters of a valid authorization request.
//
//nolint:goconst // the names of the parameters repeat across the tables
func authorizeParams() url.Values {
	return url.Values{
		"client_id": {clientURL}, "redirect_uri": {redirectURL}, "response_type": {"code"},
		"code_challenge": {challengeVal}, "code_challenge_method": {"S256"}, "state": {"xyz"},
		"resource": {resourceURL},
	}
}

// authorize sends GET /oauth/authorize with params.
func (r *rig) authorize(params url.Values) *httptest.ResponseRecorder {
	r.t.Helper()

	return r.get(oauth.PathAuthorize + "?" + params.Encode())
}

// pending runs a valid authorization request through the real endpoint with
// edit applied to its parameters and returns the sealed request the UI is sent.
func (r *rig) pending(edit func(url.Values)) string {
	r.t.Helper()

	params := authorizeParams()
	if edit != nil {
		edit(params)
	}

	rec := r.authorize(params)

	to, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || rec.Code != http.StatusFound || to.Path != "/oauth/consent" {
		r.t.Fatalf("authorize = %d %q (%v), want a redirect to the consent page", rec.Code, rec.Header().Get("Location"), err)
	}

	return to.Query().Get("request")
}

// errorBody is the exact body of an API failure with this code and message.
func errorBody(code, message string) string {
	return `{"error":{"code":"` + code + `","message":"` + message + `"}}` + "\n"
}

// bodyInternal is what a client is told for any Internal failure.
const bodyInternal = `{"error":{"code":"internal","message":"internal error"}}` + "\n"

// bodyUnauth is the one answer to a request without a valid credential.
const bodyUnauth = `{"error":{"code":"unauthenticated","message":"not signed in"}}` + "\n"

// loggedCodes are the codes of what the rig logged, in order.
func (r *rig) loggedCodes() []string {
	codes := make([]string, len(r.logged))
	for i, failure := range r.logged {
		codes[i] = failure.Code
	}

	return codes
}

// b64 is the unpadded base64url the sealed request is sent as.
func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// b64decode is the inverse of b64.
func b64decode(text string) ([]byte, error) {
	out, err := base64.RawURLEncoding.Strict().DecodeString(text)
	if err != nil {
		return nil, fmt.Errorf("decode %q: %w", text, err)
	}

	return out, nil
}

// queryPrefix is what a response URL starts with when its parameters are added to
// redirect, a redirect URI that may already have a query, or end where one would
// start.
func queryPrefix(redirect string) string {
	switch {
	case strings.HasSuffix(redirect, "?") || strings.HasSuffix(redirect, "&"):
		return redirect
	case strings.Contains(redirect, "?"):
		return redirect + "&"
	default:
		return redirect + "?"
	}
}

// addedParams is the parameters a response URL adds to redirect: the location
// must be redirect followed by a query.
func addedParams(t *testing.T, location, redirect string) url.Values {
	t.Helper()

	prefix := queryPrefix(redirect)

	rest, found := strings.CutPrefix(location, prefix)
	if !found {
		t.Fatalf("location = %q, want it to start with %q", location, prefix)
	}

	params, err := url.ParseQuery(rest)
	if err != nil {
		t.Fatalf("the added query %q does not parse: %v", rest, err)
	}

	return params
}

// verifierVal is the PKCE verifier whose S256 challenge is challengeVal (the
// example of RFC 7636 appendix B).
const verifierVal = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"

// formType is the media type of the standard OAuth endpoints.
const formType = "application/x-www-form-urlencoded"

// otherClientURL is a second client, which has its own document.
const otherClientURL = "https://other.example.org/client.json"

// postRaw sends body, as it is, to path as a form.
func (r *rig) postRaw(path, body string) *httptest.ResponseRecorder {
	r.t.Helper()

	return r.serve(request{method: http.MethodPost, target: path, body: body, contentType: formType})
}

// postForm sends values to path as a form.
func (r *rig) postForm(path string, values url.Values) *httptest.ResponseRecorder {
	r.t.Helper()

	return r.postRaw(path, values.Encode())
}

// approve runs a valid authorization request, with edit applied, through the real
// authorization endpoint and consent as userA, creating a new agent, and returns
// the code the client is sent.
func (r *rig) approve(edit func(url.Values)) string {
	r.t.Helper()

	return r.approveFor(userA, edit)
}

// approveFor is approve as the user owner.
func (r *rig) approveFor(owner string, edit func(url.Values)) string {
	r.t.Helper()

	params := authorizeParams()
	if edit != nil {
		edit(params)
	}

	text := r.pending(edit)
	cookie, _ := r.signIn(owner)

	rec := r.consent(cookie, approval(r.t, text, "Claude Code"))

	return redirectOf(r.t, rec, params.Get("redirect_uri")).Get("code")
}

// codeForm is the token request that exchanges code, as the client of the
// authorization requests above sends it.
func codeForm(code string) url.Values {
	return url.Values{
		"grant_type": {"authorization_code"}, "code": {code}, "redirect_uri": {redirectURL},
		"client_id": {clientURL}, "code_verifier": {verifierVal},
	}
}

// refreshForm is the token request that exchanges a refresh token.
func refreshForm(token string) url.Values {
	return url.Values{"grant_type": {"refresh_token"}, "refresh_token": {token}, "client_id": {clientURL}}
}

// tokenBody is a successful token response, decoded with its numbers kept as
// the text that was sent.
type tokenBody struct {
	members map[string]any

	access, refresh, idToken, scope string
}

// decodeNumbers decodes a JSON object keeping every number as a json.Number, so
// a test can tell an integer from a float.
func decodeNumbers(t *testing.T, body []byte) map[string]any {
	t.Helper()

	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.UseNumber()

	var doc map[string]any

	err := decoder.Decode(&doc)
	if err != nil {
		t.Fatalf("the body %q is not a JSON object: %v", body, err)
	}

	return doc
}

// wantInteger asserts that value is a number written as a plain integer within
// 2^53-1, which every client reads back exactly, and returns it.
func wantInteger(t *testing.T, name string, value any) int64 {
	t.Helper()

	number, isNumber := value.(json.Number)
	if !isNumber {
		t.Fatalf("%s = %#v, want a number", name, value)
	}

	parsed, err := strconv.ParseInt(number.String(), 10, 64)
	if err != nil || parsed > 1<<53-1 || parsed < -(1<<53-1) {
		t.Fatalf("%s = %s, want an integer within 2^53-1: %v", name, number, err)
	}

	return parsed
}

// member returns a string member, which must be there.
func member(t *testing.T, members map[string]any, name string) string {
	t.Helper()

	value, isString := members[name].(string)
	if !isString {
		t.Fatalf("%s = %#v in %v, want a string", name, members[name], members)
	}

	return value
}

// wantTokens asserts a 200 token response and decodes it.
func wantTokens(t *testing.T, rec *httptest.ResponseRecorder) tokenBody {
	t.Helper()

	wantNotCachedJSON(t, rec, http.StatusOK)

	members := decodeNumbers(t, rec.Body.Bytes())

	out := tokenBody{
		members: members, access: member(t, members, "access_token"), refresh: member(t, members, "refresh_token"),
		scope: member(t, members, "scope"),
	}

	if members["id_token"] != nil {
		out.idToken = member(t, members, "id_token")
	}

	return out
}

// oauthDescriptions are the fixed texts the routes give each error code.
func oauthDescriptions() map[string]string {
	return map[string]string{
		"invalid_request": "the request is missing a parameter, repeats one, or has one that is not valid",
		"invalid_client":  "the client could not be identified",
		"invalid_grant": "the code or refresh token is not valid, or was issued to another client, " +
			"or the redirect URI or code verifier does not match",
		"unsupported_grant_type":  "the grant type is not supported",
		"invalid_scope":           "the scope is not valid for the resource",
		"invalid_target":          "the resource is missing or is not one this server issues tokens for",
		"server_error":            "internal error",
		"temporarily_unavailable": "",
	}
}

// wantOAuthError asserts an RFC 6749 section 5.2 error: the status, a body of
// exactly error and error_description, the code, and (for the codes whose text
// the routes fix) the text.
func wantOAuthError(t *testing.T, rec *httptest.ResponseRecorder, status int, code string) {
	t.Helper()

	wantNotCachedJSON(t, rec, status)

	var body map[string]string

	err := json.Unmarshal(rec.Body.Bytes(), &body)
	if err != nil || len(body) != 2 || body["error"] != code || body["error_description"] == "" {
		t.Fatalf("the body %q is not exactly {error: %s, error_description}: %v", rec.Body, code, err)
	}

	if want := oauthDescriptions()[code]; want != "" && body["error_description"] != want {
		t.Errorf("error_description = %q, want %q", body["error_description"], want)
	}
}

// wantNotCachedJSON asserts the status of a JSON answer that is never cached.
func wantNotCachedJSON(t *testing.T, rec *httptest.ResponseRecorder, status int) {
	t.Helper()

	if rec.Code != status || rec.Header().Get("Content-Type") != jsonType ||
		rec.Header().Get("Cache-Control") != noStore {
		t.Fatalf("= %d %q %q, want %d JSON that is not cached", rec.Code, rec.Header().Get("Content-Type"), rec.Body, status)
	}
}

// wantBoundaryError asserts an error the boundary itself answered on an OAuth
// route (a media type, a size): the status, and an invalid_request in the RFC 6749
// error format, with the boundary's own text.
func wantBoundaryError(t *testing.T, rec *httptest.ResponseRecorder, status int) {
	t.Helper()

	var body map[string]string

	err := json.Unmarshal(rec.Body.Bytes(), &body)
	if rec.Code != status || err != nil || len(body) != 2 || body["error"] != "invalid_request" ||
		body["error_description"] == "" {
		t.Fatalf("= %d %q (%v), want %d with invalid_request", rec.Code, rec.Body, err, status)
	}
}

// signingPublic is the public half of the deployment's signing key, and its key ID.
func signingPublic(t *testing.T) (*rsa.PublicKey, string) {
	t.Helper()

	key, err := config.ParseSigningKey(testSigningKey)
	if err != nil {
		t.Fatal(err)
	}

	return &key.Private().PublicKey, key.KeyID()
}

// verifiedIDToken verifies an ID token as a relying party does, with the standard
// library alone and the key the key set publishes, and returns its header and
// claims decoded. The header must be exactly the fixed one.
func verifiedIDToken(t *testing.T, token string) map[string]any {
	t.Helper()

	public, kid := signingPublic(t)

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("the ID token %q has %d parts, want 3", token, len(parts))
	}

	signature, err := b64decode(parts[2])
	if err != nil {
		t.Fatal(err)
	}

	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))

	err = rsa.VerifyPKCS1v15(public, crypto.SHA256, digest[:], signature)
	if err != nil {
		t.Fatalf("the signature does not verify against the published key: %v", err)
	}

	header, err := b64decode(parts[0])
	if err != nil || string(header) != `{"alg":"RS256","kid":"`+kid+`","typ":"JWT"}` {
		t.Fatalf("header = %q (%v), want the fixed RS256 header with kid %s", header, err, kid)
	}

	claims, err := b64decode(parts[1])
	if err != nil {
		t.Fatal(err)
	}

	return decodeNumbers(t, claims)
}

// tokenOf generates a well-formed token of the kind, which nothing stores.
func tokenOf(t *testing.T, tag secret.Tag) string {
	t.Helper()

	token, err := secret.Generate(&sequence{reads: 1 << 40}, tag)
	if err != nil {
		t.Fatal(err)
	}

	return token
}

// exchanged approves a request (edited by edit) and exchanges its code, and
// returns the tokens.
func (r *rig) exchanged(edit func(url.Values)) tokenBody {
	r.t.Helper()

	return wantTokens(r.t, r.postForm(oauth.PathToken, codeForm(r.approve(edit))))
}

// exchangedFor is exchanged for another client, whose document the rig serves
// first: the grant is that client's, as the code form's client_id is.
func (r *rig) exchangedFor(client string) tokenBody {
	r.t.Helper()

	r.net.answers[client] = served(document(client, redirectURL))

	code := r.approve(setParam("client_id", client))

	return wantTokens(r.t, r.postForm(oauth.PathToken, withParams(codeForm(code), setParam("client_id", client))))
}

// hashOfToken is the SHA-256 of a token's text, which is what the store records.
func hashOfToken(token string) []byte {
	sum := secret.Hash(token)

	return sum[:]
}

// productionTable is the resource table of the deployment under test.
func productionTable() resource.Table { return resource.Select(apiOrigin) }

// signInKeyScoped is signInKey for userA, with a key whose scope list, and the
// agent's, are the given JSON lists.
func (r *rig) signInKeyScoped(agent, keyScope, agentScope string) string {
	r.t.Helper()

	issued, err := auth.IssueUserAPIKey(r.signer, r.signID, r.now, time.Hour)
	if err != nil {
		r.t.Fatalf("IssueUserAPIKey: %v", err)
	}

	r.creds.keys[string(issued.Hash)] = store.ActiveAPIKey{
		ID: issued.ID, UserID: userA, Role: roleMember, ExpiresAt: issued.ExpiresAt, AgentID: agent,
		AgentScopes: agentScope, Scope: keyScope,
	}

	return "Bearer " + issued.Token
}

// drop removes the parameter from a form.
func drop(name string) func(url.Values) { return func(v url.Values) { v.Del(name) } }

// twice sends the parameter a second time, with the value it has.
func twice(name string) func(url.Values) { return func(v url.Values) { v.Add(name, v.Get(name)) } }

// withParams applies every edit to a copy of form.
func withParams(form url.Values, edits ...func(url.Values)) url.Values {
	out := url.Values{}
	maps.Copy(out, form)

	for _, edit := range edits {
		if edit != nil {
			edit(out)
		}
	}

	return out
}

// wantFormEndpoint asserts what the boundary does to a POST route that takes a
// form and nothing else, in the RFC 6749 error format and before any handler
// runs: a body that is JSON, text, multipart, a form with a charset it should not
// name, or no type at all, is a 415; a body one over the route's limit is a 413;
// every method but POST is a 405 that says so. The store is never asked.
func wantFormEndpoint(t *testing.T, path string, maxBody int64) {
	t.Helper()

	form := formType
	post := func(body, contentType string) request {
		return request{method: http.MethodPost, target: path, body: body, contentType: contentType}
	}

	tests := map[string]struct {
		request request
		status  int
	}{
		"a JSON body":       {post(`{"token":"x"}`, ""), http.StatusUnsupportedMediaType},
		"no content type":   {post("token=x", "-"), http.StatusUnsupportedMediaType},
		"plain text":        {post("token=x", "text/plain"), http.StatusUnsupportedMediaType},
		"multipart":         {post("token=x", "multipart/form-data; boundary=x"), http.StatusUnsupportedMediaType},
		"a charset":         {post("token=x", form+"; charset=latin1"), http.StatusUnsupportedMediaType},
		"a body over limit": {post("token="+strings.Repeat("a", int(maxBody)), form), http.StatusRequestEntityTooLarge},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			r := newRig(t)

			wantBoundaryError(t, r.serve(tt.request), tt.status)

			if len(r.store.calls) != 0 || r.handed != 0 {
				t.Errorf("store calls %+v and %d ids for a request the boundary refused", r.store.calls, r.handed)
			}
		})
	}

	for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		t.Run(method+" is not POST", func(t *testing.T) {
			t.Parallel()

			rec := newRig(t).serve(request{method: method, target: path})

			if rec.Code != http.StatusMethodNotAllowed || rec.Header().Get("Allow") != http.MethodPost {
				t.Errorf("= %d Allow %q, want 405 with POST", rec.Code, rec.Header().Get("Allow"))
			}
		})
	}
}

// all reports whether every condition holds: a test asserts a grant of facts with
// it, so that the assertion is one statement.
func all(conditions ...bool) bool { return !slices.Contains(conditions, false) }
