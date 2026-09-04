package state

import (
	"reflect"
	"testing"
)

func TestSettingsRoundTripDeterministic(t *testing.T) {
	t.Parallel()
	parsed, err := ParseSettings([]byte("# legacy\nUSE_TMPFS_RULES=false\nVALUE=with=equals and spaces\r\n\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := Settings{"USE_TMPFS_RULES": "false", "VALUE": "with=equals and spaces"}
	if !reflect.DeepEqual(parsed, want) {
		t.Fatalf("settings = %#v", parsed)
	}
	encoded, err := MarshalSettings(Settings{"Z": "last", "A": "first"})
	if err != nil {
		t.Fatal(err)
	}
	if string(encoded) != "A=first\nZ=last\n" {
		t.Fatalf("encoded = %q", encoded)
	}
}

func TestSettingsRejectMalformedAndDuplicate(t *testing.T) {
	t.Parallel()
	for _, input := range []string{
		"bad key=value\n",
		"MISSING\n",
		"DUP=1\nDUP=2\n",
		"NUL=a\x00b\n",
	} {
		if _, err := ParseSettings([]byte(input)); err == nil {
			t.Errorf("ParseSettings(%q) succeeded", input)
		}
	}
	if _, err := MarshalSettings(Settings{"X": "line\nbreak"}); err == nil {
		t.Fatal("newline value encoded")
	}
}
