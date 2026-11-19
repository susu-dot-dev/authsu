package jws_test

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"go/ast"
	"go/doc"
	"go/parser"
	"go/token"
	"maps"
	"os"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/jws"
)

// splitToken splits a compact JWS into its three parts and decodes each with
// the strict base64url decoder, so padding or another alphabet fails.
func splitToken(t *testing.T, token string) [3][]byte {
	t.Helper()

	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("token has %d parts: %q", len(parts), token)
	}

	var decoded [3][]byte

	for i, part := range parts {
		if part == "" || strings.ContainsAny(part, "=+/") {
			t.Fatalf("part %d is empty or not unpadded base64url: %q", i, part)
		}

		bytes, err := base64.RawURLEncoding.Strict().DecodeString(part)
		if err != nil {
			t.Fatalf("part %d: %v", i, err)
		}

		decoded[i] = bytes
	}

	return decoded
}

// signed signs the standard claims and returns the token with its parts
// decoded.
func signed(t *testing.T, claims idTokenClaims) (string, [3][]byte) {
	t.Helper()

	token, err := jws.Sign(testKey(t), testKeyID, claims)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	return token, splitToken(t, token)
}

// verifies reports whether the standard library accepts the signature of a
// token's first two parts.
func verifies(t *testing.T, token string) bool {
	t.Helper()

	parts := strings.Split(token, ".")
	digest := sha256.Sum256([]byte(parts[0] + "." + parts[1]))

	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("signature: %v", err)
	}

	return rsa.VerifyPKCS1v15(&testKey(t).PublicKey, crypto.SHA256, digest[:], signature) == nil
}

// TestSignIsVerifiedByTheStandardLibrary is the differential test: the token is
// taken apart and checked with the standard library alone, never with this
// package.
func TestSignIsVerifiedByTheStandardLibrary(t *testing.T) {
	t.Parallel()

	token, parts := signed(t, standardClaims())

	if !verifies(t, token) {
		t.Error("the standard library does not verify the signature")
	}

	if len(parts[2]) != testKey(t).Size() {
		t.Errorf("signature is %d bytes, want %d", len(parts[2]), testKey(t).Size())
	}
}

// TestSignedPartsDecode: the header and claims decode, with encoding/json, to
// what was signed, escapes included.
func TestSignedPartsDecode(t *testing.T) {
	t.Parallel()

	claims := standardClaims()
	_, parts := signed(t, claims)

	var header map[string]string

	err := json.Unmarshal(parts[0], &header)
	if err != nil {
		t.Fatalf("header: %v", err)
	}

	want := map[string]string{"alg": "RS256", "kid": testKeyID, "typ": "JWT"}
	if !maps.Equal(header, want) {
		t.Errorf("header = %v, want %v", header, want)
	}

	var decoded idTokenClaims

	err = json.Unmarshal(parts[1], &decoded)
	if err != nil {
		t.Fatalf("payload: %v", err)
	}

	if decoded != claims {
		t.Errorf("claims = %+v, want %+v", decoded, claims)
	}
}

// TestVerificationIsReal: a changed payload, header or signature fails the same
// check, so the test above proves something.
func TestVerificationIsReal(t *testing.T) {
	t.Parallel()

	token, _ := signed(t, standardClaims())

	for name, tampered := range map[string]string{
		"payload":   splitReplace(token, 1, b64([]byte(`{"sub":"other"}`))),
		"header":    splitReplace(token, 0, b64([]byte(`{"alg":"none"}`))),
		"signature": splitReplace(token, 2, b64(make([]byte, testKey(t).Size()))),
	} {
		if verifies(t, tampered) {
			t.Errorf("a token with a changed %s verified", name)
		}
	}
}

func b64(data []byte) string { return base64.RawURLEncoding.EncodeToString(data) }

func splitReplace(token string, index int, value string) string {
	parts := strings.Split(token, ".")
	parts[index] = value

	return strings.Join(parts, ".")
}

// TestSignIsDeterministic: PKCS #1 v1.5 has no randomness, so the same inputs
// give the same token, and a changed claim, key ID or key changes it.
func TestSignIsDeterministic(t *testing.T) {
	t.Parallel()

	claims := map[string]any{"a": 1}

	first, err := jws.Sign(testKey(t), testKeyID, claims)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	second, err := jws.Sign(testKey(t), testKeyID, claims)
	if err != nil || first != second {
		t.Errorf("tokens differ: %v\n%q\n%q", err, first, second)
	}

	other, err := jws.Sign(testKey(t), "other", claims)
	if err != nil || other == first {
		t.Errorf("a changed key ID gave the same token: %v", err)
	}

	changed, err := jws.Sign(testKey(t), testKeyID, map[string]any{"a": 2})
	if err != nil || changed == first {
		t.Errorf("changed claims gave the same token: %v", err)
	}
}

// TestHeaderBytesAreConstant: the header is these bytes and no others, for any
// key ID, so no caller choice can alter "alg" or "typ" or add a member.
func TestHeaderBytesAreConstant(t *testing.T) {
	t.Parallel()

	for name, kid := range map[string]string{
		"test key ID":     testKeyID,
		"one character":   "a",
		"all alphabets":   "A-_9",
		"longest allowed": strings.Repeat("z", 64),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			token, err := jws.Sign(testKey(t), kid, map[string]any{})
			if err != nil {
				t.Fatalf("Sign(%q): %v", kid, err)
			}

			parts := splitToken(t, token)
			header, payload := parts[0], parts[1]

			want := `{"alg":"RS256","kid":"` + kid + `","typ":"JWT"}`
			if string(header) != want {
				t.Errorf("header = %s, want %s", header, want)
			}

			if string(payload) != "{}" {
				t.Errorf("payload = %s", payload)
			}
		})
	}
}

// TestSignRefuses: every number is an integer within 2^53-1, a JWT's claims are
// a JSON object, whatever encoding/json refuses is refused, a key ID is
// base64url only (so it cannot inject into the header), and no key or a key the
// algorithm cannot sign with is an error, never a panic or a partial token.
func TestSignRefuses(t *testing.T) {
	t.Parallel()

	for _, tt := range signCases() {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			key := tt.key
			if key == nil && !tt.nilKey {
				key = testKey(t)
			}

			token, err := jws.Sign(key, tt.kid, tt.claims)
			if (err == nil) != tt.ok {
				t.Fatalf("err = %v, want ok = %v", err, tt.ok)
			}

			if !tt.ok && token != "" {
				t.Errorf("a refusal returned a token: %q", token)
			}
		})
	}
}

// productionFiles parses the package's non-test source files.
func productionFiles(t *testing.T, mode parser.Mode) (*token.FileSet, []*ast.File) {
	t.Helper()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ReadDir: %v", err)
	}

	fset := token.NewFileSet()

	var files []*ast.File

	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}

		file, err := parser.ParseFile(fset, name, nil, mode)
		if err != nil {
			t.Fatalf("ParseFile(%s): %v", name, err)
		}

		files = append(files, file)
	}

	if len(files) == 0 {
		t.Fatal("no production files")
	}

	return fset, files
}

// TestTheExportedAPIIsExactlySign reads the package's own source: the only
// exported identifier is Sign, so there is no parse, verify, decode or claims
// type to extend into one.
func TestTheExportedAPIIsExactlySign(t *testing.T) {
	t.Parallel()

	_, files := productionFiles(t, 0)

	var exported []string

	for _, file := range files {
		for _, decl := range file.Decls {
			exported = append(exported, exportedNames(decl)...)
		}
	}

	sort.Strings(exported)

	if !slices.Equal(exported, []string{"Sign"}) {
		t.Errorf("exported = %v, want [Sign]", exported)
	}
}

// TestThePackageCommentCarriesTheWarning: the warning is in the package
// documentation, word for word.
func TestThePackageCommentCarriesTheWarning(t *testing.T) {
	t.Parallel()

	fset, files := productionFiles(t, parser.ParseComments)

	pkg, err := doc.NewFromFiles(fset, files, "github.com/susu-dot-dev/authsu/internal/jws")
	if err != nil {
		t.Fatalf("NewFromFiles: %v", err)
	}

	const warning = "authsu only signs JWTs, and every byte is server-controlled. " +
		"If authsu ever has to read or verify a JWT, replace this whole package with a vetted " +
		"crypto library; do not extend it to parse."

	text := strings.Join(strings.Fields(pkg.Doc), " ")
	if !strings.Contains(text, warning) {
		t.Errorf("package doc does not state the warning:\n%s", text)
	}
}

// TestNoJWTLibrary: the package uses the standard library only.
func TestNoJWTLibrary(t *testing.T) {
	t.Parallel()

	_, files := productionFiles(t, parser.ImportsOnly)

	for _, file := range files {
		for _, spec := range file.Imports {
			path := strings.Trim(spec.Path.Value, `"`)
			if strings.Contains(strings.SplitN(path, "/", 2)[0], ".") {
				t.Errorf("imports %s, which is not the standard library", path)
			}
		}
	}
}

// exportedNames lists the exported identifiers a declaration introduces,
// including exported methods and fields of declared types.
func exportedNames(decl ast.Decl) []string {
	var names []string

	switch decl := decl.(type) {
	case *ast.FuncDecl:
		if decl.Name.IsExported() {
			names = append(names, decl.Name.Name)
		}
	case *ast.GenDecl:
		for _, spec := range decl.Specs {
			names = append(names, specNames(spec)...)
		}
	}

	return names
}

func specNames(spec ast.Spec) []string {
	var names []string

	switch spec := spec.(type) {
	case *ast.TypeSpec:
		if spec.Name.IsExported() {
			names = append(names, spec.Name.Name)
		}
	case *ast.ValueSpec:
		for _, name := range spec.Names {
			if name.IsExported() {
				names = append(names, name.Name)
			}
		}
	}

	return names
}
