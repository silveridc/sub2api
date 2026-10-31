//go:build unit

package service

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

type releaseRepoRecordingClient struct {
	repo    string
	release *GitHubRelease
}

func (c *releaseRepoRecordingClient) FetchLatestRelease(_ context.Context, repo string) (*GitHubRelease, error) {
	c.repo = repo
	return c.release, nil
}

func (c *releaseRepoRecordingClient) FetchRecentReleases(_ context.Context, repo string, _ int) ([]*GitHubRelease, error) {
	c.repo = repo
	return []*GitHubRelease{c.release}, nil
}

func (c *releaseRepoRecordingClient) DownloadFile(context.Context, string, string, int64) error {
	panic("DownloadFile should not be called")
}

func (c *releaseRepoRecordingClient) FetchChecksumFile(context.Context, string) ([]byte, error) {
	panic("FetchChecksumFile should not be called")
}

func newReleaseRepoTestService(repo string, client *releaseRepoRecordingClient) *UpdateService {
	return NewUpdateServiceWithRepo(&updateServiceCacheStub{}, client, "0.2.19-mysql", "release", repo)
}

func TestUpdateServiceReleaseRepoDefaultsToForkRepository(t *testing.T) {
	client := &releaseRepoRecordingClient{
		release: &GitHubRelease{TagName: "v0.2.19-mysql", Assets: []GitHubAsset{{Name: "sub2api_0.2.19-mysql_linux_amd64.tar.gz"}}},
	}
	info, err := newReleaseRepoTestService("", client).CheckUpdate(context.Background(), true)
	require.NoError(t, err)
	require.Equal(t, githubRepo, client.repo)
	require.Equal(t, "silveridc/sub2api", client.repo)
	require.False(t, info.HasUpdate)
}

func TestUpdateServiceReleaseRepoUsesConfiguredRepository(t *testing.T) {
	client := &releaseRepoRecordingClient{release: &GitHubRelease{TagName: "v0.2.19"}}
	svc := newReleaseRepoTestService("  Wei-Shaw/sub2api  ", client)
	require.Equal(t, "Wei-Shaw/sub2api", svc.releaseRepo())

	info, err := svc.CheckUpdate(context.Background(), true)
	require.NoError(t, err)
	require.Equal(t, "Wei-Shaw/sub2api", client.repo)
	require.False(t, info.HasUpdate)
}

func TestUpdateServiceReleaseRepoFeedsRollbackList(t *testing.T) {
	client := &releaseRepoRecordingClient{
		release: &GitHubRelease{
			TagName: "v0.2.19-mysql",
			HTMLURL: "https://github.com/silveridc/sub2api/releases/tag/v0.2.19-mysql",
		},
	}
	svc := NewUpdateServiceWithRepo(&updateServiceCacheStub{}, client, "0.2.19-mysql.2", "release", "")
	versions, err := svc.ListRollbackVersions(context.Background())
	require.NoError(t, err)
	require.Equal(t, "silveridc/sub2api", client.repo)
	require.Len(t, versions, 1)
	require.Equal(t, "0.2.19-mysql", versions[0].Version)
}

func TestCompareVersionsWithForkSuffix(t *testing.T) {
	tests := []struct {
		name    string
		current string
		latest  string
		want    int
	}{
		{"same release", "0.2.19-mysql", "0.2.19-mysql", 0},
		{"hotfix is newer", "0.2.19-mysql", "0.2.19-mysql.2", -1},
		{"hotfix is older", "0.2.19-mysql.3", "0.2.19-mysql.2", 1},
		{"numeric hotfix beats lexicographic", "0.2.19-mysql.2", "0.2.19-mysql.10", -1},
		{"different suffix families", "0.2.19-mysql.1", "0.2.19-rc.2", -1},
		{"upstream number wins", "0.2.19-mysql.9", "0.2.20", -1},
		{"current number wins", "0.2.20-mysql", "0.2.19-mysql.9", 1},
		{"suffix ignored against bare version", "0.2.19-mysql.2", "0.2.19", 0},
		{"bare version against suffix", "0.2.19", "0.2.19-mysql.2", 0},
		{"v prefix still works", "v0.2.19-mysql", "v0.2.19-mysql.1", -1},
		{"bare upstream unchanged", "0.2.19", "0.2.19", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, compareVersions(tt.current, tt.latest))
		})
	}
}

func TestUpdateServiceDetectsSameNumberHotfix(t *testing.T) {
	client := &releaseRepoRecordingClient{release: &GitHubRelease{TagName: "v0.2.19-mysql.2"}}
	svc := NewUpdateServiceWithRepo(&updateServiceCacheStub{}, client, "0.2.19-mysql", "release", "")
	info, err := svc.CheckUpdate(context.Background(), true)
	require.NoError(t, err)
	require.True(t, info.HasUpdate)
	require.Equal(t, "0.2.19-mysql.2", info.LatestVersion)
}
