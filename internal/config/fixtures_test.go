package config_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"maps"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/config"
)

// The reasons a signing key is refused, as the substring of the error that says
// which check refused it.
const (
	reasonNotSet    = "is not set"
	reasonOneLine   = "one line"
	reasonBase64    = "base64url"
	reasonPKCS8     = "PKCS#8"
	reasonTrailing  = "trailing data"
	reasonNotRSA    = "not an RSA"
	reasonBits      = "bits"
	reasonExponent  = "exponent"
	spareBitsSuffix = "A"
)

// fixtureKey2048KeyID is the key ID of fixtureKey2048, spelled out so a change
// to how it is derived is a deliberate edit of the tests too.
const fixtureKey2048KeyID = "lUrNZ_imvj0"

func encode(der []byte) string { return base64.RawURLEncoding.EncodeToString(der) }

// fixtureDER decodes a base64url fixture.
func fixtureDER(t *testing.T, value string) []byte {
	t.Helper()

	der, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		t.Fatalf("fixture is not base64url: %v", err)
	}

	return der
}

// fixtureRSA parses a fixture with the standard library, independently of
// config.
func fixtureRSA(t *testing.T, value string) *rsa.PrivateKey {
	t.Helper()

	parsed, err := x509.ParsePKCS8PrivateKey(fixtureDER(t, value))
	if err != nil {
		t.Fatalf("ParsePKCS8PrivateKey: %v", err)
	}

	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("fixture is a %T, not RSA", parsed)
	}

	return key
}

func marshalPKCS8(t *testing.T, key any) string {
	t.Helper()

	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("MarshalPKCS8PrivateKey: %v", err)
	}

	return encode(der)
}

func signingEnv(value string) func(string) string {
	return func(name string) string {
		if name == config.SecretOAuthSigningKey {
			return value
		}

		return ""
	}
}

// refusedKey is a value OAUTH_SIGNING_KEY must be refused with, and the reason
// that is given.
type refusedKey struct {
	value  string
	reason string
}

// refusedSigningKeys is every kind of wrong value, built from the valid
// fixture.
func refusedSigningKeys(t *testing.T) map[string]refusedKey {
	t.Helper()

	refused := badEncodings(t)
	maps.Copy(refused, badDER(t))
	maps.Copy(refused, badKeys(t))

	return refused
}

// badEncodings are values that are not one line of strict base64url.
func badEncodings(t *testing.T) map[string]refusedKey {
	t.Helper()

	valid := fixtureDER(t, fixtureKey2048)

	stdAlphabet := base64.RawStdEncoding.EncodeToString(valid)
	if !strings.ContainsAny(stdAlphabet, "+/") {
		t.Fatal("fixture has no + or /: the standard-alphabet case would be vacuous")
	}

	// One byte more than the key gives a last character with four spare bits,
	// which must be zero: "A" is the canonical one and "B" sets a spare bit.
	// Without Strict the decoder would take "B" and drop the bit.
	spare := encode(append(bytes.Clone(valid), 0x00))
	if !strings.HasSuffix(spare, spareBitsSuffix) {
		t.Fatalf("spare = ...%q, want a canonical last character", spare[len(spare)-1:])
	}

	nonCanonical := spare[:len(spare)-1] + "B"

	_, err := base64.RawURLEncoding.DecodeString(nonCanonical)
	if err != nil {
		t.Fatalf("the lenient decoder refuses it too: %v", err)
	}

	head, tail := fixtureKey2048[:100], fixtureKey2048[100:]

	return map[string]refusedKey{
		"empty":                       {value: "", reason: reasonNotSet},
		"std alphabet":                {value: stdAlphabet, reason: reasonBase64},
		"std alphabet, padded":        {value: base64.StdEncoding.EncodeToString(valid), reason: reasonBase64},
		"url alphabet, padded":        {value: base64.URLEncoding.EncodeToString(valid) + "=", reason: reasonBase64},
		"padding appended":            {value: fixtureKey2048 + "==", reason: reasonBase64},
		"trailing newline":            {value: fixtureKey2048 + "\n", reason: reasonOneLine},
		"trailing CRLF":               {value: fixtureKey2048 + "\r\n", reason: reasonOneLine},
		"leading newline":             {value: "\n" + fixtureKey2048, reason: reasonOneLine},
		"newline inside":              {value: head + "\n" + tail, reason: reasonOneLine},
		"carriage return inside":      {value: head + "\r" + tail, reason: reasonOneLine},
		"trailing space":              {value: fixtureKey2048 + " ", reason: reasonBase64},
		"space inside":                {value: head + " " + tail, reason: reasonBase64},
		"tab inside":                  {value: head + "\t" + tail, reason: reasonBase64},
		"quoted":                      {value: `"` + fixtureKey2048 + `"`, reason: reasonBase64},
		"not base64":                  {value: "!!!!", reason: reasonBase64},
		"non-canonical trailing bits": {value: nonCanonical, reason: reasonBase64},
		"one over the length bound":   {value: strings.Repeat("A", config.MaxSigningKeyChars+1), reason: reasonOneLine},
	}
}

// badDER are values that are base64url but not one PKCS#8 key.
func badDER(t *testing.T) map[string]refusedKey {
	t.Helper()

	valid := fixtureDER(t, fixtureKey2048)
	rsaKey := fixtureRSA(t, fixtureKey2048)

	flipped := bytes.Clone(valid)
	flipped[len(flipped)-5] ^= 0x01

	public, err := x509.MarshalPKIXPublicKey(&rsaKey.PublicKey)
	if err != nil {
		t.Fatalf("MarshalPKIXPublicKey: %v", err)
	}

	pkcs1 := x509.MarshalPKCS1PrivateKey(rsaKey)

	return map[string]refusedKey{
		"hex":                        {value: strings.Repeat("ab", 100), reason: reasonPKCS8},
		"garbage DER":                {value: encode([]byte("not a key at all")), reason: reasonPKCS8},
		"truncated DER":              {value: encode(valid[:len(valid)-10]), reason: reasonPKCS8},
		"one byte":                   {value: encode(valid[:1]), reason: reasonPKCS8},
		"PKCS#1":                     {value: encode(pkcs1), reason: reasonPKCS8},
		"SPKI public key":            {value: encode(public), reason: reasonPKCS8},
		"trailing data":              {value: encode(append(bytes.Clone(valid), 0x00)), reason: reasonTrailing},
		"trailing garbage":           {value: encode(append(bytes.Clone(valid), "trailing"...)), reason: reasonTrailing},
		"corrupt private parameters": {value: encode(flipped), reason: reasonPKCS8},
	}
}

// badKeys are well-formed PKCS#8 keys that are not an accepted signing key.
func badKeys(t *testing.T) map[string]refusedKey {
	t.Helper()

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	_, edKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}

	return map[string]refusedKey{
		"EC key":      {value: marshalPKCS8(t, ecKey), reason: reasonNotRSA},
		"ed25519 key": {value: marshalPKCS8(t, edKey), reason: reasonNotRSA},
		"1024 bits":   {value: fixtureKey1024, reason: reasonBits},
		"8192 bits":   {value: fixtureKey8192, reason: reasonBits},
		"e = 3":       {value: fixtureKey2048E3, reason: reasonExponent},
		"e = 65539":   {value: fixtureKey2048E65539, reason: reasonExponent},
	}
}

// Signing-key fixtures: PKCS#8 DER RSA private keys as base64url without padding,
// generated once with `openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:N`
// (and `-pkeyopt rsa_keygen_pubexp:E` for the odd exponents), then
// `-outform DER`, base64, `tr '+/' '-_'` and `tr -d '='`. They guard nothing: they
// exist so no test pays for generating a 4096 or 8192 bit key.
const (
	fixtureKey2048 = "" +
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

	fixtureKey4096 = "" +
		"MIIJQQIBADANBgkqhkiG9w0BAQEFAASCCSswggknAgEAAoICAQCTYrMZGBCSJkRw0Kc0sLUxor9dVyDr" +
		"14psg7a1jj7BKH05VLIDSMh7pzThyd6mSRincM_CTdOzCXw5FsM1o-C3y5SNeiTvk-luyyLi1XlIDbRa" +
		"mUawKHOSaW17HEDOTgEEpA7cNY4L-eJsYXpW_vZoX3Li5T4tV69qlMUGmJRdLrjxSHUF2U6bzyp3VTvP" +
		"Pz3adweqmxjW5xEhcqqRDFNaqWCl1s5es0_apo6Le11yQKhrz5OqMk8Cp70Plxo3xpsgTeBPL3fJhYeR" +
		"-DaJtOc-U01blkPNtbntdFGQZU6DoaKZykPXJ-pn8mAQA6efsrhNk29_d4WsFuBJa91-6a1LE-mJTPOz" +
		"abx3s0taZaAFLxm1w9tjPvc8su6RWAIiLYytdcnBUZZtkBJYG1Z3nSQDLSsYvqQcXzrQFIf0IYHJzZCG" +
		"ynmS6H149r_cHCKDZavpzM9eQppRwML-N0-eChI72QBozXcMi4ullazRzgxD3zeHrNfUeiU-ifvg3H_Y" +
		"iR1UTUEl7bIMiqd6qIhOvJf_Xmmc1yJtd2OH4CNDgooYph0ygviVYMrxH2zld_3uAUNq_dCAkur5tuOQ" +
		"HG-vEsuLxM3VUwtTmjw5r-eXguuOG0gYFkVz1L7OIhudC7FNN9QQi7hn_MsdyDiN9HoIEm1Q6AufoTbn" +
		"QVxpM1uHeW26pwIDAQABAoICACvtv57rnsjI0h5j-mpIfwEX1nzOIthYioAUdAlCJ-8vj79eQJ6c-3Br" +
		"omXn4s5iPBBwHeR2iPI0kgt7_twGh8yQR6sxbD_iMLHepvvAD-GLgCV-yORpciUB-mk2vxQeiMwmz-0P" +
		"o1JrfPK7zRiP7samKFp7ZGBkYbrdM6pnINVzPxlfdM20-uqSwUAHLgfz_A4Y6zaM-sbW4TK8eB06dL-x" +
		"e0aCs0jjnhn4CcWGFBChN_HGUWdpjkYm08GJUn2sWwEyZPiFF-l_PKyjtDGwMzpO3uA89eGi2BNv1323" +
		"zEKMkyfOcxD2azXnNn2fcT82qBsrJhDygWuM9_W6Si7xHD6wGkU1keAIx2Zfqbm5yuY82PPu20R0HnwE" +
		"hC9RhkvrqtBNiBAxQCxX72jcchSAiizsFdLo2vxpRoLfMim6BQLYWqS3iwmyeOFOLEmxDNOR7S41BsAH" +
		"Qbv6ihfFPRdsfy0hmuZ4Azh6oJIMrUAyoLZJn0gC6i_e79EDzCIprPptlH59I7QX1c0qiwZ1PuM9_sqY" +
		"KuJO4a6ATMIixR83JdZnZVyu0u2jAgGpIx1VujnVVYWu9Tn5SXOnHeWcikltDfhRc6Z5ErCxXMDM7Yw-" +
		"ZBD3nx9oJGSRA1ULZpMfUvrosWNjKoDl6pPFnxsfJ284aLE_NjvC_nNuxWllC91pMWQdAoIBAQDC_QKV" +
		"NmjaSnyALEOEi86ZLsfqpxAKvAH1_Tp11eVsC37zi_KPpE-QFF0p8TgGx9VW034RQ2gPfurSmz9f3Tu1" +
		"Cjr4CR_9KwWWPV8Na22dmRW2Hb5hOmDk9q2vXiXoGNKgZtAqyUsW_QH52rOHgRgfcJbyq2hLWiZnuTCZ" +
		"1heEfRsXzSicIVneAD-XmMnQBgOfzXqfzqLdfst8Ejq6xtE8sna0lOVd7n_asuxeT7FoAZJPTBySpqHu" +
		"tnpj3q4Oj25pCaB0yckDz9-OxSYBXRsDoIFW978tsi7NWGsj5OcnhQl5rxOiBm_oPfOm29LawCIwZbJd" +
		"TggkKTTYovXKwr1lAoIBAQDBgJp0_bRQjvZlSDxz90TXZCcuihqv7iPV-n7x4OMKld6Q6j4qOsEV9DTB" +
		"CUlUcVNZUTcau6XVMmAnRhTTRfx16MqDJYA4q7xycz-UsBd0rBWsYYxM5Z9TEnITxrW3FukGKzt0hJxI" +
		"cweWt_5kGSBUZrrOz_injaLB_Z8-wybFFyt459I0-f7feX-Xnkb37rR4RZ3kGzc2_O4Kmo1wa1Nz7kY-" +
		"6Cdg7o8RpLdKyxuVqwupwSE9kDFf89Rj0d77r0oGD-tIioD5UB0dD4eVWuZz6TVrw5Gnr67A4gM-dV4H" +
		"FBIUGh33jU4g8gdHuD51hE9zOT3ebEbWDR-uQoHMJS0bAoIBAFyiVLrMqY2jO3itDrqGrPULS4DIM4_V" +
		"99yEnGRk5OSqpXpQ70CcoAvkEMqfRa26_DiOq2LKMkLCWg8KIFaLxRTiMleqBh-Bc9sHdwPqGJ55nt3x" +
		"TYPldyjvpF4fDUUxnccEcTsSfHEEbA7mfsoOY4Z0N9I76oV546r9SQCcvHl98gQhvHxIP-h_F7cOqDoC" +
		"0W_2753CTo-J8GQWSP54--ipJEnwPvOcHfOpcy_vDmpJ7NdtYlmtflrpKEYQAYL7U0nlf-xb_PqppByw" +
		"vriBIhdcBnZpptKvxxpZOjVIRyT4SCMeMOaVxk6AOCP6ZTb1doill9JKAwYi6W9OJBVa5R0CggEAfslB" +
		"6xf01rflkBVVrvI8hBjWZ3ML62xQxLqeBORCP0RVkYQ5-TeIHldlXXo1NwQOBb7mKTj8foXEZNdRe-Em" +
		"eydt0aJ3siosjp0e8tCyfbrndIxx_kySKT8zyetwUyfKxUT8busY74uXVFT4dSPVgBfTnQC9vyNZmlwQ" +
		"xHHf7FGzJURYAmgvbMPSK0kE3Rzl2MxcmQKQGhJ98iq0NA3On25nTn6UlrmYuom_o10TlOx-9tpZaloZ" +
		"T_KWnlT8EtMW4IP7uQsvWKv6d3kecGkgCKCsZRC-Vi4RhcZRM9J5KpAnDE7UhchrgcCzrnV1T1DDMg82" +
		"j49IlqYAtRBUtatCMwKCAQB2WaGKBTbRZK-ma_KNJvcs7o10RgWiolqEQdwe_MUdw4z6YfNbHExdoaFG" +
		"4Lrx9id92TlIGaMWqv3qnQUJ0GAY3q-7R2hHgidKzUYW8KZB94x5XoT5QV_UCf2B5ELv3SLFrozm0wcY" +
		"7TsBIflH0Dfc3aZOuZD6QYyEIuPOzaLK-x1Im2Q35ojVL0H4-ZGRe6NH0aF1qmbziIJC6e4cBboeASjy" +
		"1arbkrEbDAfUV08WbYUo4NCQGrcwr0807cpgPDaeAkAdhbDCvtM8KfBQLxP0116QSIxieIXwKgUq_8gS" +
		"sVt8nE1qMvGgDXBt471EAfaZs2u0Tg28RXP95B4kaWJc"

	fixtureKey1024 = "" +
		"MIICdwIBADANBgkqhkiG9w0BAQEFAASCAmEwggJdAgEAAoGBAMrlGmNqOoqoYVJQFnGSv9XIfWBAJ6PI" +
		"fVUQvKPtpMSC3mawQMZzfvG0IQqFaES3p2XzWy0xawiZ6RuiJbvaQU3Zr4Gqk5WnxJC_Ic-X0bM5bBny" +
		"iOiJ1613mUGMhMqedNlhG4REwDSm783lfLlXlyJ4kUJocZcueITzSRcNJYnbAgMBAAECgYBfZYUYxTOt" +
		"SiooJ5vF3rfv7op0nPWGXpf_TRVFBlF4TAgBxFFQfbFsN8NpTPyPgsJkfx2ZjCjFLIicA4s2XhJhj30L" +
		"mb1x_tuHyksqZRX-aoxf4JUYZAGp7L8LCz15Hc6Ab549Kg8AFa3p5XOxTHg-Ahao55FJth-7X0aFvQhb" +
		"UQJBAPL_MKmzdZO_-Ho2adVv0wInpnCDULZfz6uz25hCB6MZGPi60lFiI8E-jykLO8Ym05pio7b8Xk26" +
		"8YzGKa0UQE8CQQDVwI7CBpfXsJivopCK_6Fv0jJ_tERjiyhubI2Y3pT2RvJSFx0eyIF6_E1hQlQcPAfd" +
		"oNQtehA5Trgc7_wvBE61AkEAnoLnPJwrY8FDln1uVmPG0s4InbabbQxdDNWbttvD3Znel0pPLfWF-2YS" +
		"vyRrzpu_RyN3RkOkRLJhJYKS5yuhswJAQeB0nuu1RG5SwF6TuaMLOBFKKv19zkgHD_E4upJuynAXIqGp" +
		"AeG9tg-oMX9luMXvjqiQe-uQsHjIWXLFACCNuQJBAJrVscg-V6rXBqaPHr6gO8W6AitXSHxPm8_RWQCk" +
		"2dbLIC9jDuyoOLOHnMcYlKTt_pctkvjn4O3bRSk9cXF_yyo"

	fixtureKey8192 = "" +
		"MIISQQIBADANBgkqhkiG9w0BAQEFAASCEiswghInAgEAAoIEAQDh3upW1Kt9EC_WIIraAF8ZlILH2Rfx" +
		"Q7vRSk1eqm-1RtMbQlyGADqHAN5xkH1URqE52Y5S_I5qldBMtkOGn4XZu1ZkrlI5kKjKzf49sCpqfuLN" +
		"lqXhk-h0jXB1_-7Fk9v2-IrLOSdRsyBa0I-KV26UJlROi50fH5DnjXdBV2-TF8yVsJSyZuc4uxn89MpV" +
		"PkOQ4Gm1C5PfuoR_x8fjbWpBlxjhtYUk0lEIsoiSnK84cvTbdULTA9MLF7UgtXXqD0UHtbemtzxt7JvI" +
		"ISeiE10Iq1txRqYnSBZGMcNC7YtulLDwlu3I5q8gdQQwmDNOVqvSECSQQjTTZINw09F7Z4DzrFblIrBY" +
		"1cOJxPrhRsuRGB8rxXFn0doDInzYFoLDzDjdZZB6Infub59sBYsjOy1Npg_CauJ88a46qr0Elz-JqsKk" +
		"pGTDErxCkETHhltJaGoLb2EWRzhsWG3KRzdbuwIR119sNgLQ9EhaO3SRX8pSox7JhfDae6khxwcRng38" +
		"Cmi-vIu-RtU4tVauTXK714uOidVR3R1XH32FnqWEM0vB65Pl_Yi-k6chQv2YzT3FvS5YqHD8JimRB35z" +
		"OdxHT6veAwgQxC9ISaPdAdN3SZdUsUAlTBoGtKo8gRfXycVezwmwBOdNkt_908GMXqk2rpP7oW-rZPuK" +
		"Lws0l1485alCeEb4DsnAS9hcGhbZlaSWEIU1RFCT2Kl7jwEobMuWMQuvDuB1fpQvTW6JBxS6UD0_b2Q0" +
		"p0Bz0ky9Em-VVAgeUrYXrUm69-9LZH3D0DC2US32-ksHaTwE3V9ziRxWQxXS1Nk3Vm9Xplbbv3gLaZVj" +
		"AYXa-OSLLIOIekHEhw5SlG0mexzWy2gmbLEOh_tLEMWJ2AnH5Sc7JtxhdWUfgJ3SqdbX3FOCkeccNZKV" +
		"nHO9A4XRBLHWkEE7EWcBXV7ZVULq-MmzPbHQBMVdP5Wl_OV-kSrpV2UHEvr-9ev8ZNM1sgxvyaPb7T0F" +
		"fbLL-xTi0PniQ4meNuIps5WNjXkz0YqSu2Sp8z2B2Z4D5ggDtC_17BF2NMAuh0miGnz2xIBs-SnGz9P0" +
		"D9cvQSkaaksheG7FqQ1Aojdb3r_apg_EC-DdVqz1Jf-dtJM6ALufqyAIGt59V6NVeKcjLLNxYE3vXahy" +
		"5FJUx5x9BuFWzJSPJX5adX_drAjPLPWFC4KQlC8LPQGcmhViWr0q3L_gw2rVLjRAl1Pgsaf6g7Es2ppf" +
		"I4MxSXnpTFBdF0XrHuuOqUt0K0gvDOFfEESh29ceJJSETXfoC0lnivtU3o_ZL_D-ftyO2eRVXQ9jZQjm" +
		"Pq7iYSxEiiGi6Vt5_VG5w4k-SQbYXebm5h6J41lHgBDJ-oaf-xHc9C-RAgMBAAECggQAC7-9rtCXLwU1" +
		"h8zfjCFy0PDRsLWRMkKUtXlI9wCkmOhbONLF306JvNYFvCCI9GZMIqc3aQesHM04LZVZg9ouazn8b3ZF" +
		"3qqwrQP0Ep9kRW_eOlV4wXghIlbtH6Y1dF-RlJIvHg0WB4Dq0O6CWO7dWKV5wzAt9x18Ox83sdVrf1pA" +
		"kRTDV1hU9LV-z5KoJ7D6cMHLndhBU-Tu2Xq54hGh8lF6wNrhVx39ixdGVWIDF0ubgwLhe_p58tzD1jS6" +
		"Mnei3pjMOcbURN-G5u0ak6qwLzBCrGzBXc-5IOObxZJ3q0PexFUFf2rId0a-9gwktxF5FI80Z7CZ8NkM" +
		"oUTTY7jpk0NGrdqVE7ni1vrBFhDJq_12OZ-mm4Dl9z3HArKBENBBsPqEfmXmmSeDQmozZ5y_aYeW0EUh" +
		"DODBcFnLRT7c1jtkro3ClAcYddntSfeqLfJZecjMYw1HWRNsepYjwgjDPcxXMVjJ4raiQNdQ4_L4oj3L" +
		"7y2hbqv6C0DAFGGFVrPv6OQD3NzwYGfGX4C11CGNJ9fxmbWHvi1sKRQshejpKugnJFKA13D0w50pddZP" +
		"PUbu7zurzOHrTZj3MeUzmR4C0aSUudKKpxb1iBx9NHpGfehObuI7hFfHdyg75kSfmKPqXBaVNYrLTffC" +
		"3Jtb7_U6y18FYQP6taBm09B_3WkQ2d0wxNR_a4sECwXrBuOf6tNZvC7q4K19kcdx4Q9-j99lzGC0CLpb" +
		"bNDJz0FnzsutwkhmWxDXPD8T3ykgSDuihxU08HW0umCgn9MRzu56CDEKyVW3uZs0FLLojg4SgS9mwFH4" +
		"55SYxaudcNIW540xiXlK0j4IiUg5SEjCm4B2rHd5xC7fDAzEiRyL0ZYpM7bNTj8FrkgjvQZk1oW_tAtv" +
		"WAz4QeEU01pV0mh_ObR050e6QipDCBCyhj6-oDfG84WZnpsfbJDL7v91wXOE8uXReb-Vi8IkwRZ6yrHI" +
		"GTKzkNSuOmw812uEZBPW4_1tHT0vPHVp8CfV1-KE681q7vJyBqG3eNH0gESG44lyDek4nNUvEF0lS1fz" +
		"vF7jH0NfAwMYgthFwJC-KjKsfgQHOupNq0gUXDqqQZL6Gvu1USs7QiKrOsphBZVe7pr50369TMEdbPu3" +
		"MIHc-5VOr7rVuOm-Wa-fFmeu9QOpBqhrPRtY9IpvroJetQa6NuOvTaU8pYrxP1P6laEMkKWv8WE-BYoL" +
		"b9nX8649n8ZBvwRVU40z7navRK_Ldsz0kMBlKrW0C_xq6dDuLkXBfCn_1y1-jLPEU_M73xIHD3NCRI_E" +
		"AjolLHqlRJZgJbxSZZLc7vdslwrHxL5isQatFZ900mfudIHbitDBADKAkhzPUpibb0eAD_RB8QKCAgEA" +
		"964W2h-w8ElhzsWvPF_Spz8CNOPTI3CkJGS6yy0eD5RUpKf7Z-vnMeOBvDzg_as2RrJh_OnM9vzKDLI6" +
		"KG852_tC9ZrqaqDsjGtNYO8NcdjMjCWBk7zDiA_nrkT7hM48oiThDZw1zX9EeYySFgDiXTeTmp-E3BXj" +
		"F9qIx2tedwEb44cFxcC8-3w3i6tkc4i8XaRGtbFuv0PpnXiWr9_bANAzuElLYnnOL_Y4BytHIMWgxBlS" +
		"NC_574hd2vbNmeuFVsxgZHGShSLfqFb4_pIi5CPcP1T8CJabsN12D1oGg18VubRaKdIploYDvPokkqm3" +
		"_Wcn7lstEwmRpeFbXXUugR07TC9r9cX6y6oXsXTArDGk8OvP3dm1-YaYKu_JAaaRI4YC91t_lOtvsHPu" +
		"cDUxOun9JAsp0DyJbA3ezKPJxDey-5cvseekOtiZTQQgOvChDIJfDrfBpXTKWYnmup8O2aofbilUF1N9" +
		"cEqwOTWlTtsaRsIXGHQy9lY9MsdmPAdW1cYTdhrWT84dpZtW8ez19MTHMyZ208rNTQ5tuycJUGMrEGaj" +
		"lhER01D5W5AtmpGTHMKRNK3HK7dPOPHTEeV4qeHidB6t0aKF7I56JRnGW52jflKtwOcFXw99PIo4gHJ_" +
		"r-7gSUg7nrMdTNSB1fc8nk1dbxOFDBaIUPp4bcmZ2JUCggIBAOl1R0sD7GqCw9esq4v_oJNG78yRR6n-" +
		"Oam8m7oEv_Q8e5K7FawjPhbLk_wIUwvEHzwJpxcmuKdcoaQxboYxCC3eCaq0MG_7EZ2KDXC7i01mKEJZ" +
		"nLxW5UFtMhi9Z7ZJQKMXwK0IYhwj0ZmE6spaeY0mmR8EdFJTkqqIXS8to5VMcuGuZ_JOxrGU3nUKO60E" +
		"KZIO5_XX9WbdhU4DWIQHD2UZDihLli5efmRVrCtoArf1Mrn5VsnDIVBZzaOgtHs_07gDTxv4vNbNA-e4" +
		"ZDio6mMOfz0u4Wm4lhj0N-z4ab9Z9fqNE5PLTeFC3Q1dRimrZGSsEu64pT0HOZLc6LLavB21UCMEs9wN" +
		"iEpw8f0JQe6TeKF9pde-4kLYSxo1w64GgODg6LLZebxiATGy5-UQJiUSAXs6r7QR7EFryl8kdEAd03PF" +
		"KBlFAFQit_NYNHLhaQCxOmAQh_Iy1y22iFTTdeRZ8lkUMkxHiZLX5rwHMj_O0yZZRkguNzp_1mZ3Yp12" +
		"OzhH0t2AWUx4_RN930vL6XpUTEhe6RSOuku_Ne7QdL_DBwe_JnYgHjj5gqxAxh19WLnuuwGw-_Z71cDv" +
		"pc0jHzcKqOTR1szLpphgPKHu5P5zHVAssPaZ-dFzfhC8F-VC3-mdyNfCXjRyohZZceCsp6Moz3NbJtdj" +
		"Ux4mdDJsF3ANAoICAEwUcrqPz4cP03ZzbM-L06ZCCYh7juis-g6fzm0Ir9ozQwjM_MHASeUeMETFIotp" +
		"IyP2OXk5zBb2MY5S1OCEwe4bsUbGTklwoxjDASLMa4HUCYjnIHVkH1_VGuKCGAyEWUWpNGQ83p4AAOWh" +
		"U2Jk5SOjJbjyVRpRss8p9qfjCEJf2dQ7Ln-_I43QazOA8zs1_j55bqrzFMS1tLYFS6w8hAYs7iYmhXx7" +
		"U-WRqUYyegfMDQUPjhuvvQNiDQpsk107ZlryLo3MASjaPH92L8fq1cLkbQwbK8vrj2l1rYUrryJ9e6vu" +
		"hV-hSdsN0WokIEXY0kaJgE-MPD1DzDR7E9iSXTWV6BgP3QbCyLX0ypBc_64lFbhXhyNrc6VxPZ66xzC1" +
		"nJGf4ZtfxMHWzBkUk2JuRHAHXhXLRA3N-pxxakXL7fdS8KytlR39vInC7Nwmb0wLjDzOcyqPMXGEfX-h" +
		"h3k90I713e-1zDnaEIcEujroip29WcXwaq29S8Y1WVkWvQWlb3v8-w9lUP10n9C19bAcjLSiGVpR72BB" +
		"RGzuCLDbXdYOkDTagldfaO1TSzVgBVIcc2b7MSVQWATKqxAf4Cj4JudwFmJ65gOl-6NdZJGu6CpOMuFj" +
		"vjGqBRFdLagCATcbdLNzGfwIrx-hf1eRU0yJRFqQAypSgaTj6v2M4p8-tP49AoICAHXe6dT9MSOBzGGb" +
		"Y622rhtOCIrvmxBANFr3yGR-O3CUDQxDeyjDTnjx5lCs30kkh2Sntv5gZYDSqyYccyI7pVaLMbRHb-FK" +
		"EVXKOwj9F9NHTfJaDmGlOfDzsgR9tNx7VbBCsNxsTCTLDOuHCYiLb62NnGflttlOKtIBMZM9Zsddpu89" +
		"QGw9y-IjOMI9HW44mMiO0Bz3IYcDN2fxFoLqkaJIqTY9G6FjwkrkWp470IuSuD7fnisWYz6PaN1BqX5E" +
		"9p-ExC9qQeXt8xfOqINW_ahvzFxWzCa1tMr6mzYBIlsjj6cmDYlkb3jZaoRx4JfvWiveGV0ASyVp_W6i" +
		"LLcI60vQnJphqHHlPzfemL9aKjjLqm9W4iHw1YpMbHbaSGcYD3_67mJGnUk47kNqgdzMb4Xt9mOCeO3g" +
		"0rkhNDcfT7aDmJxuIdXIWecg9GFf2nNaTcq0sLWKAymM88m3zFOPxIk7xLmnEdIjmFlUusGanItM4J0P" +
		"HAYbl3To0JZBlr_LzxCWaue9AtkyiQyLU--QD9zcrPspOGNRwMu3ygI-q4Oac3U81K11f-ziRVC1D5Ia" +
		"FG8kErVC56RGV-Em3j6ZigwfTLDjJaGW_REYHeTgmivCcT1mox6PFWvj9PV8ElCFmEn6iUoub6PpcN75" +
		"4B5A7g7Z7wveLNk44-FoJujCXH8NAoICAGUS2gL9GxuMPTonONIx037tLnsxbXC9txJwnY3PHVhKwsp6" +
		"-OgquA6BRmahmW5pm7NOXFCLf2_z01fFqVnpMlWqg5rWpOuOQb9qP_KC_scgXxIr7y3vU919esQwjAga" +
		"QCySzY8aVTi3PrMGqHU3Jm_1ikUnc7M3fcQvzLs-xKyII9bUcdLUbKemQAmomdy54KKlf18G2t7g5A2t" +
		"Qr95iSGY03kN6M6RtX45wIHEd-csVYm5f5rgHBLFv8uQOgeWEULZ217-6Cq4G7uc6xbsP0EEnzxBV8fZ" +
		"d_fJZ-j_0OCXctOqEuwJb3YFXaJwth8wanNjj-QSA9wxI-jZ3ig4-HW4IKcsq0Vp5YQm-p5SHKPQXkIM" +
		"W3d-u9KA99grxdS5BCu6NyaoCy0H0Yx2eLJjq6R691jDzHGndiCwiVe9g5w5fG8JLNvMv0L1bNczg0gr" +
		"YmWNrIXZBe3fOnkpcrV5i8vOxhX7IQPY0sPnw7u7rEnz3F06LKnNWNphrWFdeVUPvA79Hn1X5rqWZJf0" +
		"dS4Y3XTDp-LRFQ8xMb09VTbsCUFAA-o0YnvKXzPe1XQbSylXYs5mnLSc5MDqtNl-m-EgCKu7NiqUA3DF" +
		"z2GwvaYwj-52qEkIoouR2IYpnLpMEBFu4R0HMpasYl9TbTkNPt6DLu639Awk1cCQ5bfchXjstMZV"

	fixtureKey2048E3 = "" +
		"MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC_oAo-5mmckKBs-JmrxhxZzVvNWfBd" +
		"AtL-g0rmzUPALHZlgPh4DS4e2GPSgZ3dIPobUsv_MdKsifOqiaQXY9gAbmYwYsSXu1nOIQHFCBXZKjhR" +
		"Or-7PdHCRjXbHa7j1S_S0StKqIWOshvqglsfVdMaqqlR27aYVZf6D7xGvpab1UHLH2-uO2aNTU7JFOTI" +
		"sViKKizikia6ZeQLgUHctr_XrzN7TLPofSJyzJ2N_spuQLPMFOpw5LUHQdGitTN1nNBye7vKQgYnHGwN" +
		"grfNtBsIrAsfWgd5L3lKmPik7sWT96B4GhfF0nrWsZzhqrunyyJlhYInKDB6U58nLJRzpqeNAgEDAoIB" +
		"AH_ABtSZm721wEilu8fZaDvePTORSuisjKms3JneLSrITu5V-vqzdBSQQoxWaT4V_BI3MqohNx2xTRxb" +
		"wrpCkABJmXWXLbp85olrVoNauTtxeuDR1Sd-i9bZeTy-dJfjdTc2HNxwWQnMEpxW52o5N2cccOE9JGWO" +
		"ZVFf0tnUZGfiWF9ABE_xO-7UUxvOLS5wSWRH388alKpGM1Wo7EnkFwrZhX1nrn0nSMiAK6jGB67RDIcV" +
		"43EfCuuZQHPBKMFqE9x-99pyhdCRi0ZVNTOIvEXJZW2caTr8zB_EtMG_6e67yunJqEv5W23SxbIKU-Gg" +
		"QvPrhKtS9ujWTFS8X5PGXOsCgYEA9QlAMKVMjT7KRGUov4O2Cd-nF-rFjDkps5t40Lwl4o-qcGOxWIoM" +
		"yJLboX-ImX7UJ1k26kWROc4U3jrFRCOeVyeL8DFg1ZZFLWJ1V_vYXLjq4w8PHf5xCLlKlBNge-AlTgNd" +
		"NE2PcMTrOhJSDB7_yzuANTvFfVSVq7L4ziI8T3UCgYEAyDL_OJEE_2hEjbo24X9S4JQXRUEku4HS42-L" +
		"DrG6ure-ett_1aK1bLMwupFNJWky-ag9KwGk6tfHErpOMi_fW4AxV9E1Z9f87cGNkASOo-cTD-vgS6JD" +
		"PmGnVW7uas24ohYOZwZNAO0KOkRJMbZa8rwkBepmQMh8gPUZNvPAzLkCgYEAo1uAIG4zCNSG2ENwf60k" +
		"BpUaD_HZCCYbzRJQiygZQbUcSu0g5bFd2wySa6pbEP84Gjt58YO2JoljPtHY2Be-5MUH9XZAjmQuHkGj" +
		"j_066HtHQgoKE_72BdDcYreVp-rDiVeTeDO09dic0WGMCBSqh30AI30uU425HSH7NBbS36MCgYEAhXdU" +
		"0GCt_5rYXnwkllTh6w1k2NYYfQE3QkpctHZ8fHp-_JJVORcjnczLJwuIw5t3URrTcgEYnI_aDHw0IXU_" +
		"klV2Oot47-VTSSuztVhfF-9iCp1AMmws1EEaOPSe8d57Frle71mIq0ixfC2GISQ8odLCrpxEKzBTAKNm" +
		"JKKAiHsCgYAUSYnEAD4OjZ3SuzbEqu5g5GfSBl4S2XWXsrq9-oFCr6p0OyUS_AJtHlDzdIkqNi76bR0c" +
		"vOsggu3McpF3PqvjntpI3axYevxV6dzZpNXnHEDup1RLdo6XFUk3yOQjPNor-sJJT_81L-YB2gymehZF" +
		"ez9EzVF04PTW93GIZr4Ivg"

	fixtureKey2048E65539 = "" +
		"MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQD0ttcokdwdtN9E96YXwZqnWBaeAA6e" +
		"u9RJx3XBqG_AEybRxnnUMKgJjAPB2HEYu1bMdEDmCCd4JjrtkLGqPJG7bo_B-mQ43tX0Ic3jDXABrSDl" +
		"myslXJyiThhT_ofgwmPqHBaScEtsBM-1UyOasHA5kDN_l1qld1SFCzFp4Kw-ftaJaNL7o_C2hihzxwrd" +
		"qU9gtKoEnNXuwUZNdc8cpt7klhg43H9JHZrkqyjfndzCyfyx4m2TT1NQNsjCKKrVciqIDFvZB1gCAdwB" +
		"gUam5QsRas5zCVmvjllzjMgVGmqs2D3RVmlCzptjfIukv94zwzHwlJfEr8wRKTXoVpr-0oTnAgMBAAMC" +
		"ggEAEugNvIW7cAtC5FPzVdjgT9ADY0_4MUQQVThNBLzc18ETixeT7_Soha9D1oUdAaGoildWY6KzYJLW" +
		"cgqJUnqxlGYIIlTZEsejMfCszcYG9tRDX2NUdegbk8mMTYxwS0EzI6ObpaKDNEFsZg3HxWLUqzyN_PAz" +
		"XNG3TxeVnRzYCFXeFACndhGd_nD--btTGp0-e7wP7UTM_ci0_UhIWzIZG-p6XxO0IwbNxmSHxgQivrmL" +
		"uvTvOHfZYPbftf6Y53Ar5p_M9x3PwzEcezjaRotMA2mKmeQCQpTZ6iBdOQU8RVis1dVL1_UvWs-KJyxD" +
		"3cedA1ELERWInpSOUDgh_aDl-wKBgQD-uHw6uQmKbDVsCaHg26Wbk06nhq5cNTE1hcs8_U63u0Z8FKm-" +
		"aHBhcS9VsrLbdxBxRfLoiCNNfbPug12BdiITy9biN8Bv81IYeCX5c5KMzAnnoj1dCqV8gsZPMng8QIrR" +
		"dMwqu7VJxYA6vN81atVUddbuAP0hcdFrcdpaQASTlwKBgQD18X03nfyMMaTs0A6mk_9jcTSbqMzwx4Hx" +
		"UAIgd06DA7SrTudT5KJ2gns-9aKXXsvTfLbqX411dB526xvOom8yQchhG8SwXIaOZbk9uX8nXzWh2pba" +
		"nP2b6fhEP7CzL3tci0P6B44_bE6lMkMgbSfjSSOwLKtq_HMdW7YVanSDMQKBgCqWvRFiaE8qNlgTfBSy" +
		"u9KV468b2afh9TqBVX2MKhr-QUhPY4upt31EgwqdJ0x4PRkZVNee7HpZi59InTKj9rrHLvJ6VwAzAKsR" +
		"ZbVKkStTQ9YtgBYkW0qFxjM_aJhpSXo1Rtt4nGAmo4Lnt-M42Uz5ZSnQMOKa7iFav2BE_3TnAoGAWONw" +
		"rrMO-WLZSofHZEDbENjtD-eP8-rQJ86KiSpjolGE7Ufp5mW0wyUZqlF7ArLcJOjpxfKdYfaFSz1SQfWR" +
		"vf3qudEC4RGd8UfSX2cYTusNukm5nvDXGz_72n9RmJ7EgwJQ18EJ17DXTlFCrUVMFdLi7HkvvUjspHuD" +
		"Wi1-ehsCgYEAhtozd0GytAtpkwkdNLQ_vAwsyqG4Sf3QV0ahy6gHBBKFeTFyxKeizkg08QvUqbCI-syx" +
		"XeIkHLYwfDuUPsrZqXSCcdDd1SceZklIT4JOlH62eVEhvinW0i0UeL5yoCPX_XOsKbVLcIndvp6JGogE" +
		"RUsMuu8wfdNkyfdzBJjM4K0"
)
