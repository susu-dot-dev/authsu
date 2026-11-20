package jws_test

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"math"
	"strings"
	"testing"
)

// testKeyID has the shape of the ones authsu uses: base64url of eight bytes.
const testKeyID = "lUrNZ_imvj0"

// testKey is an RSA key, parsed from a fixture: generating one is the slow part
// of a test, and the signer takes the key it is given.
func testKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()

	der, err := base64.RawURLEncoding.DecodeString(testKeyDER)
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}

	parsed, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		t.Fatalf("ParsePKCS8PrivateKey: %v", err)
	}

	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("fixture is a %T", parsed)
	}

	return key
}

// standardClaims has the shape of the claims authsu signs, with a nonce that
// needs JSON escaping.
func standardClaims() idTokenClaims {
	return idTokenClaims{
		Iss: "https://auth.example.com", Sub: "0123", Aud: "https://client.example/c.json",
		Iat: 1700000000, Exp: 1700000300, AuthTime: 1699999000, Nonce: `n"<&>`,
	}
}

// idTokenClaims has the shape of the claims authsu signs.
type idTokenClaims struct {
	Iss      string `json:"iss"`
	Sub      string `json:"sub"`
	Aud      string `json:"aud"`
	Iat      int64  `json:"iat"`
	Exp      int64  `json:"exp"`
	AuthTime int64  `json:"auth_time"` //nolint:tagliatelle // OpenID Connect names this claim auth_time
	Nonce    string `json:"nonce,omitempty"`
}

const safe = 1<<53 - 1

// signCase is one call to Sign and whether it must succeed. A nil key is the
// shared test key unless nilKey asks for no key at all.
type signCase struct {
	name   string
	key    *rsa.PrivateKey
	nilKey bool
	kid    string
	claims any
	ok     bool
}

// signCases are the inputs Sign is tried with: every refusal, and the accepted
// values that sit beside them.
func signCases() []signCase {
	var cases []signCase

	cases = append(cases, numberCases()...)
	cases = append(cases, notObjectCases()...)
	cases = append(cases, unencodableCases()...)
	cases = append(cases, keyIDCases()...)

	return append(cases,
		signCase{name: "no key", nilKey: true, kid: testKeyID, claims: map[string]any{}},
		signCase{name: "a key with no parameters", key: emptyKey(), kid: testKeyID, claims: map[string]any{}},
	)
}

// numberCases are claims whose numbers must be integers within 2^53-1, wherever
// they are.
func numberCases() []signCase {
	type single struct {
		N any `json:"n"`
	}

	number := func(name string, n any, ok bool) signCase {
		return signCase{name: "number " + name, kid: testKeyID, claims: single{N: n}, ok: ok}
	}
	claims := func(name string, claims any, ok bool) signCase {
		return signCase{name: name, kid: testKeyID, claims: claims, ok: ok}
	}

	return []signCase{
		number("zero", 0, true),
		number("one", 1, true),
		number("negative", -5, true),
		number("2^53-1", int64(safe), true),
		number("-(2^53-1)", int64(-safe), true),
		number("2^53", int64(safe)+1, false),
		number("-(2^53)", -int64(safe)-1, false),
		number("2^53+1", int64(safe)+2, false),
		number("max int64", int64(math.MaxInt64), false),
		number("min int64", int64(math.MinInt64), false),
		number("max uint64", uint64(math.MaxUint64), false),
		number("uint64 at the bound", uint64(safe), true),
		number("uint64 over", uint64(safe)+1, false),
		number("whole float", float64(1700000000), true),
		number("fraction", 1.5, false),
		number("tiny fraction", 1e-7, false),
		number("large float", 1e21, false),
		number("float over the bound", float64(1<<60), false),
		number("string of a big int", "9007199254740993", true),
		claims("number nested in an object", map[string]any{"a": map[string]any{"b": int64(safe) + 1}}, false),
		claims("number nested in an array", map[string]any{"a": []any{1, 2, int64(safe) + 1}}, false),
		claims("numbers nested and safe", map[string]any{"a": []any{1, map[string]any{"b": 2}}}, true),
		claims("no numbers", map[string]any{"a": "b", "c": true, "d": nil}, true),
		claims("empty object", map[string]any{}, true),
		claims("the real claims", idTokenClaims{
			Iss: "https://auth.example.com", Sub: "u", Aud: "c",
			Iat: 1700000000, Exp: 1700000300, AuthTime: 1699999000,
		}, true),
		claims("the real claims, exp too large",
			idTokenClaims{Iss: "i", Sub: "u", Aud: "c", Iat: 1, Exp: int64(safe) + 1, AuthTime: 1}, false),
	}
}

// notObjectCases are values that are valid JSON but not an object.
func notObjectCases() []signCase {
	notObject := func(name string, claims any) signCase {
		return signCase{name: "not an object: " + name, kid: testKeyID, claims: claims}
	}

	return []signCase{
		notObject("nil", nil),
		notObject("string", "a"),
		notObject("number", 1),
		notObject("bool", true),
		notObject("array", []string{"a"}),
		notObject("pointer", (*idTokenClaims)(nil)),
		notObject("nil map", map[string]any(nil)),
		notObject("nil list", []any(nil)),
	}
}

// unencodableCases are values encoding/json refuses.
func unencodableCases() []signCase {
	unencodable := func(name string, claims any) signCase {
		return signCase{name: "unencodable: " + name, kid: testKeyID, claims: claims}
	}

	return []signCase{
		unencodable("channel", make(chan int)),
		unencodable("func", func() {}),
		unencodable("NaN", map[string]float64{"a": math.NaN()}),
		unencodable("Inf", map[string]float64{"a": math.Inf(1)}),
	}
}

// keyIDCases are key IDs Sign refuses.
func keyIDCases() []signCase {
	badKid := func(name, kid string) signCase {
		return signCase{name: "bad key ID: " + name, kid: kid, claims: map[string]any{}}
	}

	return []signCase{
		badKid("empty", ""),
		badKid("quote", `a"b`),
		badKid("backslash", `a\b`),
		badKid("space", "a b"),
		badKid("newline", "a\nb"),
		badKid("padding", "ab=="),
		badKid("plus", "a+b"),
		badKid("slash", "a/b"),
		badKid("dot", "a.b"),
		badKid("non-ASCII", "é"),
		badKid("NUL", "a\x00b"),
		badKid("JSON injected", `a","alg":"none`),
		badKid("too long", strings.Repeat("a", 65)),
	}
}

// emptyKey is a key with no parameters, which the standard library refuses to
// sign with rather than panic.
func emptyKey() *rsa.PrivateKey { return &rsa.PrivateKey{} }

// testKeyDER is a 2048 bit PKCS#8 RSA key, base64url, made with openssl for tests only.
const testKeyDER = "" +
	"MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQC6lbbip9uVmgRj75gQslm3gzvarRtR" +
	"vhlPPms2PFrWam92j3ys4yCcRxp1_CERC63ySVNywcx-kLSU8k64bv2rx8j3gE7zJd8CXj4k9oPKFsju" +
	"EiHq9rnPTdE_ZAG17MBSOw3YlniBVENw6NVod9ho5YQXhsOlmaQmeTRPnAIWwXHwVPjmXFDJKq2UdZyE" +
	"kXlN3fUE_esC2nAoGAK5z23R1wIVtidTHxjHYAyaQs59qSj1zKNXdduXWRlnZW0CpFRuBoCP2p_aicy4" +
	"9EhkzAhtC-burVKr-XKu8e2-_4cSlAxtbyCDNLV53-_NIYbrq7Y6kuOKPvt9xboUPb0Rm7exAgMBAAEC" +
	"ggEATG5TslkMbCXhMobNBdnpQnExrYxHqp5yg7GP_XGPzFFhQ3HXooKPszS1NCuJ6A-eu6cp1dJpUFc6" +
	"geEYOhjNNPbr7ebTcGrNBY1Ra5bHuZrHyC4JUtSqnK7Fzm_K-5j11zl1nIlW57N6xN-7u8WMErwh9fkw" +
	"X7-mLFRuB0Zi3KrCSAIepMKYiQlLyIKCFasg-BhI-IUV8EFwLhlqVTFPE2UADDdiUKGehItd9-l4hEsL" +
	"VuPHRx2_2bDSfhy-hUqo9lxEuFWaxKSGOj4Je5eQ-XMvnLa5fFfeIG7ZpJrjxv2p2jLfa5-P359CeTvL" +
	"8dM42BaH5YztwY8f7seLNhYYmQKBgQDfCZvvd1JvGrXeKpRkss25LZFBk0uaAH26OBqrF_BOXA26jpSB" +
	"QzU7n_Id6USPhBlterWPietw0D0GxXlyK2lh1nAr-EDjp50pPyjWurkO8tuzovuxr6TvGgLxD9OEfe0A" +
	"Z4DjkTGC8mu4rfzdXe_wsFPWeSz4-9hmVCQFA2mvuwKBgQDWKPSD8TXjBR6xh6-lGUqLIhl2zrCYejIj" +
	"bshMt6yKxSSeimXror9cb_D4LUn-r66EhEWmIcBwKU273cHTRDurgISLlt9prFKgPs2jzrhSNVtZf1Ff" +
	"MnFddFmFZU1OQiwtwywvzNnzMxugTDAmvoIEGhdhyFeIbLX8XVU5D2wxgwKBgQDKNbMLi3nQQz4p2x7I" +
	"oRdE0RxFgJ5lVBao816ySbTTxj-oKMZY3y7vDNb86VUAbLqE-GCNb3RmxlTdw8GUkeksC7eNFbj27Sre" +
	"j2WeMJHBDMvFdHmPIfh90m5iUX_qOiTaXfyL1UI3P0QMnqmHpTf5VlPcOeZdIi-SrqwtY2e5KwKBgBUU" +
	"lPUD4k0FbP8Gnyh-M9M8OQtzzvhDVvob5oV-svI585_TebLXI0UDE9IqCxWRz3jl2EFBI0MnHaq3amPU" +
	"XJdGIEXpRPaO6tcxN2a_a29UJzjJCoZ3XadYU5OI5DIm21hp1MijvnRs_HQr67V0nTGwK8sJQGyCXuuH" +
	"eGMUfI7nAoGBANqYDqC2Gcw48cFNZMna-V3sxqYW1kspK9-eEDJSj7Bq8h-DSJ2LGO9DBcrn0P9l1mdC" +
	"zxRBnHpC3sp77Nn8uePUhZ8VFQDtQiAAsnikd2Qk_iPONSk5h9fLuvlkEjSEOIEFTIgMyYRl3RyUyZRC" +
	"2za5CsmpmJmPl6pC739OKBgO"
