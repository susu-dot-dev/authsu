package result_test

import (
	"errors"
	"strconv"
	"testing"

	"github.com/susu-dot-dev/authsu/internal/result"
)

var (
	errBoom    = errors.New("boom")
	errWrapped = errors.New("wrapped")
)

func TestConstructorsAndGet(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		res     result.Result[int]
		want    int
		wantErr error
	}{
		"ok":                         {res: result.Ok(3), want: 3},
		"fail":                       {res: result.Fail[int](errBoom), wantErr: errBoom},
		"of ok":                      {res: result.Of(4, nil), want: 4},
		"of err":                     {res: result.Of(0, errBoom), wantErr: errBoom},
		"zero":                       {res: result.Result[int]{}},
		"of discards value on error": {res: result.Of(9, errBoom), wantErr: errBoom},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := tt.res.Get()
			if got != tt.want || !errors.Is(err, tt.wantErr) {
				t.Errorf("Get = (%d, %v), want (%d, %v)", got, err, tt.want, tt.wantErr)
			}

			if !errors.Is(tt.res.Err(), tt.wantErr) {
				t.Errorf("Err = %v, want %v", tt.res.Err(), tt.wantErr)
			}
		})
	}
}

func TestChain(t *testing.T) {
	t.Parallel()

	double := func(n int) int { return n * 2 }
	label := func(n int) (string, error) { return "n=" + strconv.Itoa(n), nil }

	tests := map[string]struct {
		in        string
		want      string
		wantErr   bool
		wantCalls int
	}{
		"all steps run": {in: "21", want: "n=42", wantCalls: 1},
		"then fails":    {in: "x", wantErr: true},
		"check fails":   {in: "-1", wantErr: true, wantCalls: 1},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			calls := 0
			positive := func(n int) error {
				calls++

				if n <= 0 {
					return errBoom
				}

				return nil
			}

			got, err := result.Of(tt.in, nil).
				Then(strconv.Atoi).
				Check(positive).
				Map(double).
				Then(label).
				Get()
			if (err != nil) != tt.wantErr || got != tt.want {
				t.Errorf("chain = (%q, %v), want (%q, err=%v)", got, err, tt.want, tt.wantErr)
			}

			if calls != tt.wantCalls {
				t.Errorf("guard calls = %d, want %d", calls, tt.wantCalls)
			}
		})
	}
}

func TestFailureSkipsEveryStep(t *testing.T) {
	t.Parallel()

	res := result.Fail[int](errBoom)

	ran := false
	res.Then(func(int) (int, error) { ran = true; return 0, nil }).
		Map(func(int) int { ran = true; return 0 }).
		Check(func(int) error { ran = true; return nil })

	if ran {
		t.Error("a step ran after a failure")
	}
}

func TestMapErr(t *testing.T) {
	t.Parallel()

	wrap := func(error) error { return errWrapped }

	failed := result.Fail[int](errBoom).MapErr(wrap).Err()
	if !errors.Is(failed, errWrapped) {
		t.Errorf("MapErr on failure = %v, want wrapped", failed)
	}

	succeeded := result.Ok(1).MapErr(wrap).Err()
	if succeeded != nil {
		t.Errorf("MapErr on success = %v, want nil", succeeded)
	}
}
