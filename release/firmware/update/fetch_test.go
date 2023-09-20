// Copyright 2023 The Armored Witness Applet authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package update

import (
	"context"
	"testing"

	"github.com/coreos/go-semver/semver"
	"github.com/transparency-dev/armored-witness-common/release/firmware/ftlog"
	"golang.org/x/mod/sumdb/note"
)

const (
	testOrigin = "testlog"
	testVkey   = "ArmoredWitnessFirmwareLog+3e6f9306+ARjETaImkiqXZCH5pk1XtfX0tHgFhi1qGIxQqT6231S1"
	testSkey   = "PRIVATE+KEY+ArmoredWitnessFirmwareLog+3e6f9306+AYJIjPyyT5wKmBQ8duU8Bwl2ZSslUmrMgwdTUChHKEag"
)

func TestFetcher(t *testing.T) {
	ctx := context.Background()
	lv := mustNewVerifier(t, testVkey)
	logClient := &fakeLogClient{
		releases: []ftlog.FirmwareRelease{
			{
				Component:  ftlog.ComponentOS,
				GitTagName: *semver.New("1.0.1"),
			},
			{
				Component:  ftlog.ComponentApplet,
				GitTagName: *semver.New("1.1.1"),
			},
		},
	}
	f, err := NewLogFetcher(ctx, logClient.GetBinary, nil, testOrigin, lv, nil)
	if err != nil {
		t.Fatalf("NewLogFetcher: %v", err)
	}

	if err := f.Scan(ctx); err != nil {
		t.Fatalf("Scan: %v", err)
	}

	os, applet, err := f.GetLatestVersions(ctx)
	if err != nil {
		t.Fatalf("GetLatestVersions(): %v", err)
	}
	if got, want := os, *semver.New("1.0.1"); got != want {
		t.Errorf("got != want (%v, %v)", got, want)
	}
	if got, want := applet, *semver.New("1.1.1"); got != want {
		t.Errorf("got != want (%v, %v)", got, want)
	}

	logClient.releases = append(logClient.releases, []ftlog.FirmwareRelease{
		{
			Component:  ftlog.ComponentOS,
			GitTagName: *semver.New("1.2.1"),
		},
		{
			Component:  ftlog.ComponentApplet,
			GitTagName: *semver.New("1.3.1"),
		},
	}...)

	if err := f.Scan(ctx); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	os, applet, err = f.GetLatestVersions(ctx)
	if err != nil {
		t.Fatalf("GetLatestVersions(): %v", err)
	}
	if got, want := os, *semver.New("1.2.1"); got != want {
		t.Errorf("got != want (%v, %v)", got, want)
	}
	if got, want := applet, *semver.New("1.3.1"); got != want {
		t.Errorf("got != want (%v, %v)", got, want)
	}
}

type fakeLogClient struct {
	releases []ftlog.FirmwareRelease
}

func (c *fakeLogClient) GetBinary(_ context.Context, release ftlog.FirmwareRelease) ([]byte, error) {
	return []byte(release.GitTagName.String()), nil
}

func mustNewVerifier(t *testing.T, p string) note.Verifier {
	t.Helper()
	v, err := note.NewVerifier(p)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return v
}
