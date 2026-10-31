package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNormalizeUpdateRepoAcceptsOwnerName(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  string
	}{
		{"", ""},
		{"   ", ""},
		{"silveridc/sub2api", "silveridc/sub2api"},
		{" Wei-Shaw/sub2api ", "Wei-Shaw/sub2api"},
		{"a1/b2.c3-d4", "a1/b2.c3-d4"},
	} {
		got, err := NormalizeUpdateRepo(tc.input)
		require.NoError(t, err, tc.input)
		require.Equal(t, tc.want, got)
	}
}

func TestNormalizeUpdateRepoRejectsMalformed(t *testing.T) {
	for _, input := range []string{
		"sub2api",
		"https://github.com/silveridc/sub2api",
		"silveridc/sub2api/extra",
		"silveridc/",
		"/sub2api",
		"/",
		"silver idc/sub2api",
		"_x/sub2api",
		"silveridc/sub api",
		"silveridc/sub#api",
	} {
		_, err := NormalizeUpdateRepo(input)
		require.Error(t, err, input)
		require.Contains(t, err.Error(), "owner/name")
	}
}
