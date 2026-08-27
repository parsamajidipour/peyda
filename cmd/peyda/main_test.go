package main

import (
	"reflect"
	"testing"
)

func TestExtractRunTarget(t *testing.T) {
	tests := []struct {
		name         string
		args         []string
		wantTarget   string
		wantFiltered []string
		wantErr      bool
	}{
		{
			name:         "target before flags",
			args:         []string{"example.com", "-p", "25"},
			wantTarget:   "example.com",
			wantFiltered: []string{"-p", "25"},
		},
		{
			name:         "target after flags",
			args:         []string{"--crawl-depth", "3", "example.com"},
			wantTarget:   "example.com",
			wantFiltered: []string{"--crawl-depth", "3"},
		},
		{
			name:         "legacy target flag",
			args:         []string{"-t", "example.com", "-p", "25"},
			wantFiltered: []string{"-t", "example.com", "-p", "25"},
		},
		{
			name:    "extra positional argument",
			args:    []string{"example.com", "extra.com"},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotTarget, gotFiltered, err := extractRunTarget(tt.args)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error")
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if gotTarget != tt.wantTarget {
				t.Fatalf("target = %q, want %q", gotTarget, tt.wantTarget)
			}
			if !reflect.DeepEqual(gotFiltered, tt.wantFiltered) {
				t.Fatalf("filtered = %#v, want %#v", gotFiltered, tt.wantFiltered)
			}
		})
	}
}
