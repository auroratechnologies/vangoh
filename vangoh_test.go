package vangoh

import (
	"bytes"
	"crypto"
	"errors"
	"fmt"
	"hash"
	"testing"
)

type testProvider struct {
	promptErr  bool
	identifier []byte
	secretKey  []byte
}

func (tp *testProvider) GetSecretKey(identifier []byte) ([]byte, error) {
	if tp.promptErr {
		return nil, errors.New("testing error")
	}
	if !bytes.Equal(tp.identifier, identifier) {
		return nil, nil
	}
	return tp.secretKey, nil
}

var tp1 = &testProvider{
	promptErr:  false,
	identifier: []byte("testIDOne"),
	secretKey:  []byte("secretKeyOne"),
}

var tp2 = &testProvider{
	promptErr:  false,
	identifier: []byte("testIDTwo"),
	secretKey:  []byte("secretKeyTwo"),
}

var tpErr = &testProvider{
	promptErr:  true,
	identifier: []byte("testIDErr"),
	secretKey:  []byte("secretKeyErr"),
}

func TestNew(t *testing.T) {
	vg := New()

	if vg.includedHeaders == nil {
		t.Error("includeHeaders not properly intialized")
	}
	if vg.keyProviders == nil {
		t.Error("keyProviders not properly intialized")
	}
	if vg.singleProvider {
		t.Error("default constructor should not create a single provider instance")
	}
	if !checkAlgorithm(vg, crypto.SHA256.New) {
		t.Error("default constructor should instantiate the algorithm to SHA256")
	}
}

func TestNewSingleProvider(t *testing.T) {
	vg := NewSingleProvider(tp1)

	if vg.includedHeaders == nil {
		t.Error("includeHeaders not properly intialized")
	}
	if vg.keyProviders == nil {
		t.Error("keyProviders not properly intialized")
	}
	if !vg.singleProvider {
		t.Error("singleProvider constructor should create a single provider instance")
	}
}

func TestAddProvider(t *testing.T) {
	vg := New()

	if len(vg.keyProviders) != 0 {
		t.Error("Wrong number of key providers in the VanGoH instance")
	}

	err := vg.AddProvider("test", tp1)
	if err != nil {
		t.Error("Should not have encountered error when adding a new provider")
	}

	if len(vg.keyProviders) != 1 {
		t.Error("Wrong number of key providers in the VanGoH instance")
	}

	err = vg.AddProvider("test", tp2)
	if err == nil {
		t.Error("Should error when trying to add multiple providers for same org tag")
	}

	if len(vg.keyProviders) != 1 {
		t.Error("Wrong number of key providers in the VanGoH instance")
	}

	err = vg.AddProvider("notTest", tp2)
	if err != nil {
		t.Error("Should not error when trying to add multiple providers for different org tags")
	}

	if len(vg.keyProviders) != 2 {
		t.Error("Wrong number of key providers in the VanGoH instance")
	}

	spvg := NewSingleProvider(tp1)

	if len(spvg.keyProviders) != 1 {
		t.Error("Wrong number of key providers in the VanGoH instance")
	}

	err = spvg.AddProvider("test", tp2)
	if err == nil {
		t.Error("Should error when trying to add second provider to single provider instance")
	}

	if len(spvg.keyProviders) != 1 {
		t.Error("Wrong number of key providers in the VanGoH instance")
	}
}

func TestAlgorithm(t *testing.T) {
	vg := New()

	if !checkAlgorithm(vg, crypto.SHA256.New) {
		t.Error("default constructor should instantiate the algorithm to SHA256")
	}

	vg.SetAlgorithm(crypto.SHA1.New)
	if !checkAlgorithm(vg, crypto.SHA1.New) {
		t.Error("Algorithm not correctly updated with SetAlgorithm method")
	}
}

func checkAlgorithm(vg *VanGoH, algo func() hash.Hash) bool {
	vga := fmt.Sprintf("%T", vg.algorithm())
	toCheck := fmt.Sprintf("%T", algo())

	return vga == toCheck
}

func TestAnchoredRegex(t *testing.T) {
	vg := New()

	err := vg.IncludeHeader("^X-Amz-.*$")

	if err != nil {
		t.Error("Including anchored regex failed")
	}
}

func TestUnanchoredRegex(t *testing.T) {
	vg := New()

	err := vg.IncludeHeader("X-Amz-.*")

	if err != nil {
		t.Error("Including unanchored regex failed")
	}
}

func TestInvalidRegex(t *testing.T) {
	vg := New()

	err := vg.IncludeHeader("X-Amz-.*[")

	if err == nil {
		t.Error("Invalid regex should have thrown an error")
	}
}
