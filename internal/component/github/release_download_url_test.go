package github

import "testing"

func TestReleaseDownloadURL_PointsAtGitHubsDownloadLinkWithEscapedSegments(t *testing.T) {
	if got := NewClient().ReleaseDownloadURL("locktivity", "epack-collector-tls", "v0.1.1", "epack-collector-tls-linux-amd64"); got != "https://github.com/locktivity/epack-collector-tls/releases/download/v0.1.1/epack-collector-tls-linux-amd64" {
		t.Errorf("default client link = %s", got)
	}
	if got := NewTestClientWithPolicy(nil, "http://127.0.0.1:8080/", nil).ReleaseDownloadURL("o", "r", "v1/../x", "a b"); got != "http://127.0.0.1:8080/o/r/releases/download/v1%2F..%2Fx/a%20b" {
		t.Errorf("test client link = %s", got)
	}
}
