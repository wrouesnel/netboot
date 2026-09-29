package ipxetrust

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"reflect"
	"testing"
)

func fp(s string) [FingerprintLen]byte { return sha256.Sum256([]byte(s)) }

func TestPatch(t *testing.T) {
	table, err := Table([][FingerprintLen]byte{IPXERootCA})
	if err != nil {
		t.Fatal(err)
	}
	if len(table) != TableLen {
		t.Fatalf("table length %d, want %d", len(table), TableLen)
	}
	image := append(append([]byte("before"), table...), "after"...)

	got, err := Trusted(image)
	if err != nil || !reflect.DeepEqual(got, [][FingerprintLen]byte{IPXERootCA}) {
		t.Fatalf("Trusted(built image) = %x, %v", got, err)
	}

	want := [][FingerprintLen]byte{fp("a"), fp("b")}
	patched, err := Patch(image, want)
	if err != nil {
		t.Fatalf("Patch: %s", err)
	}
	if len(patched) != len(image) || !bytes.HasPrefix(patched, []byte("before")) || !bytes.HasSuffix(patched, []byte("after")) {
		t.Fatalf("Patch changed bytes outside the table")
	}
	if got, err := Trusted(patched); err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("Trusted(patched) = %x, %v; want %x", got, err, want)
	}
	if got, _ := Trusted(image); !reflect.DeepEqual(got, [][FingerprintLen]byte{IPXERootCA}) {
		t.Fatalf("Patch modified its input")
	}

	// A patched image can be patched again.
	full := make([][FingerprintLen]byte, Slots)
	for i := range full {
		full[i] = fp(string(rune('c' + i)))
	}
	repatched, err := Patch(patched, full)
	if err != nil {
		t.Fatalf("Patch(patched): %s", err)
	}
	if got, err := Trusted(repatched); err != nil || !reflect.DeepEqual(got, full) {
		t.Fatalf("Trusted(repatched) = %x, %v; want %x", got, err, full)
	}
}

func TestPatchErrors(t *testing.T) {
	table, err := Table([][FingerprintLen]byte{IPXERootCA})
	if err != nil {
		t.Fatal(err)
	}
	one := [][FingerprintLen]byte{fp("a")}

	if _, err := Patch([]byte("no table here"), one); !errors.Is(err, ErrNoTable) {
		t.Errorf("image without a table: got %v, want ErrNoTable", err)
	}
	if _, err := Patch(append(bytes.Clone(table), table...), one); err == nil {
		t.Errorf("image with two tables: no error")
	}
	if _, err := Patch(table[:TableLen-1], one); err == nil {
		t.Errorf("truncated table: no error")
	}
	if _, err := Patch(table, nil); err == nil {
		t.Errorf("no fingerprints: no error")
	}
	if _, err := Patch(table, make([][FingerprintLen]byte, Slots+1)); err == nil {
		t.Errorf("too many fingerprints: no error")
	}
}

func TestCDefine(t *testing.T) {
	if got, want := CDefine([]byte{0x01, 0xab, 0x00}), "0x01,0xab,0x00"; got != want {
		t.Errorf("CDefine = %q, want %q", got, want)
	}
}
