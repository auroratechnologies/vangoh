package vangoh

import (
	"errors"
	"testing"
)

type testProvider struct {
	promptErr bool
	noMatch   bool
}

func (tp *testProvider) GetSecretKey(identifier []byte) ([]byte, error) {
	if tp.promptErr {
		return nil, errors.New("Testing Error")
	}
	if tp.noMatch {
		return nil, nil
	}
	return []byte("testingKey"), nil
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
}

func TestNewSingleProvider(t *testing.T) {
	vg := NewSingleProvider(&testProvider{})

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
