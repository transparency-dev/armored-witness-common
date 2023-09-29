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
	"encoding/json"
	"testing"

	"github.com/coreos/go-semver/semver"
	"github.com/transparency-dev/armored-witness-common/release/firmware/ftlog"
	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/serverless-log/api/layout"
	"github.com/transparency-dev/serverless-log/testonly"
	"golang.org/x/mod/sumdb/note"

	"github.com/transparency-dev/formats/log"
	fmtlog "github.com/transparency-dev/formats/log"
	slog "github.com/transparency-dev/serverless-log/pkg/log"
)

const (
	testOrigin = "testlog"
	testVkey   = "ArmoredWitnessFirmwareLog+3e6f9306+ARjETaImkiqXZCH5pk1XtfX0tHgFhi1qGIxQqT6231S1"
	testSkey   = "PRIVATE+KEY+ArmoredWitnessFirmwareLog+3e6f9306+AYJIjPyyT5wKmBQ8duU8Bwl2ZSslUmrMgwdTUChHKEag"
)

func TestBinPath(t *testing.T) {
	for _, test := range []struct {
		r    ftlog.FirmwareRelease
		want string
	}{
		{
			r:    ftlog.FirmwareRelease{Component: ftlog.ComponentOS, GitTagName: *semver.New("1.0.1")},
			want: "trusted-os/1.0.1/trusted_os.elf",
		}, {
			r:    ftlog.FirmwareRelease{Component: ftlog.ComponentOS, GitTagName: *semver.New("1.9.1")},
			want: "trusted-os/1.9.1/trusted_os.elf",
		}, {
			r:    ftlog.FirmwareRelease{Component: ftlog.ComponentApplet, GitTagName: *semver.New("7.7.7")},
			want: "trusted-applet/7.7.7/trusted_applet.elf",
		}, {
			r:    ftlog.FirmwareRelease{Component: ftlog.ComponentBoot, GitTagName: *semver.New("0.0.0")},
			want: "boot/0.0.0/armored-witness-boot.imx",
		}, {
			r:    ftlog.FirmwareRelease{Component: ftlog.ComponentRecovery, GitTagName: *semver.New("2.0.0")},
			want: "recovery/2.0.0/armory-ums.imx",
		},
	} {
		if got, _ := BinaryPath(test.r); got != test.want {
			t.Errorf("Got %q want %q", got, test.want)
		}
	}
}

func TestFetcher(t *testing.T) {
	ctx := context.Background()
	lv, ls := mustNewVerifierSigner(t)

	for _, test := range []struct {
		desc     string
		releases [][]ftlog.FirmwareRelease
		want     [][]ftlog.FirmwareRelease
	}{
		{
			desc: "Rolling updates",
			releases: [][]ftlog.FirmwareRelease{
				{
					{Component: ftlog.ComponentOS, GitTagName: *semver.New("1.0.1")},
					{Component: ftlog.ComponentApplet, GitTagName: *semver.New("1.1.1")},
				},
				{
					{Component: ftlog.ComponentOS, GitTagName: *semver.New("1.2.1")},
					{Component: ftlog.ComponentApplet, GitTagName: *semver.New("1.3.1")},
				},
			},
			want: [][]ftlog.FirmwareRelease{
				{
					{Component: ftlog.ComponentOS, GitTagName: *semver.New("1.0.1")},
					{Component: ftlog.ComponentApplet, GitTagName: *semver.New("1.1.1")},
				},
				{
					{Component: ftlog.ComponentOS, GitTagName: *semver.New("1.2.1")},
					{Component: ftlog.ComponentApplet, GitTagName: *semver.New("1.3.1")},
				},
			},
		}, {
			desc: "Finds latest within multiple revs",
			releases: [][]ftlog.FirmwareRelease{
				{
					{Component: ftlog.ComponentOS, GitTagName: *semver.New("1.0.1")},
					{Component: ftlog.ComponentApplet, GitTagName: *semver.New("1.1.1")},
					{Component: ftlog.ComponentOS, GitTagName: *semver.New("1.0.2")},
					{Component: ftlog.ComponentApplet, GitTagName: *semver.New("2.0.1")},
				},
			},
			want: [][]ftlog.FirmwareRelease{
				{
					{Component: ftlog.ComponentOS, GitTagName: *semver.New("1.0.2")},
					{Component: ftlog.ComponentApplet, GitTagName: *semver.New("2.0.1")},
				},
			},
		}, {
			desc: "ignores later lower versions",
			releases: [][]ftlog.FirmwareRelease{
				{
					{Component: ftlog.ComponentOS, GitTagName: *semver.New("1.1.1")},
					{Component: ftlog.ComponentApplet, GitTagName: *semver.New("1.1.1")},
					{Component: ftlog.ComponentOS, GitTagName: *semver.New("1.0.2")},
					{Component: ftlog.ComponentApplet, GitTagName: *semver.New("1.0.1")},
				},
			},
			want: [][]ftlog.FirmwareRelease{
				{
					{Component: ftlog.ComponentOS, GitTagName: *semver.New("1.1.1")},
					{Component: ftlog.ComponentApplet, GitTagName: *semver.New("1.1.1")},
				},
			},
		}, {
			desc: "Use log precedence",
			releases: [][]ftlog.FirmwareRelease{
				{
					{Component: ftlog.ComponentOS, GitTagName: *semver.New("1.0.1+banana")},
					{Component: ftlog.ComponentApplet, GitTagName: *semver.New("1.1.1+banana")},
					{Component: ftlog.ComponentOS, GitTagName: *semver.New("1.0.1+apple")},
					{Component: ftlog.ComponentApplet, GitTagName: *semver.New("1.1.1+apple")},
				},
			},
			want: [][]ftlog.FirmwareRelease{
				{
					{Component: ftlog.ComponentOS, GitTagName: *semver.New("1.0.1+apple")},
					{Component: ftlog.ComponentApplet, GitTagName: *semver.New("1.1.1+apple")},
				},
			},
		},
	} {
		t.Run(test.desc, func(t *testing.T) {
			// Set up an in-memory serverless log to test against.
			ms := testonly.NewMemStorage()
			initLog(ctx, t, ms)

			if lr, lw := len(test.releases), len(test.want); lr != lw {
				t.Fatalf("Test invalid num releases %d != num want %d", lr, lw)
			}

			for i := range test.releases {

				addReleasesToLog(ctx, t, ms, testOrigin, lv, ls, test.releases[i])

				f, err := NewFetcher(ctx, FetcherOpts{
					BinaryFetcher:         getBinary,
					LogFetcher:            ms.Fetcher(),
					LogOrigin:             testOrigin,
					LogVerifier:           lv,
					PreviousCheckpointRaw: nil})
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

				for _, want := range test.want[i] {
					var got semver.Version
					switch want.Component {
					case ftlog.ComponentApplet:
						got = applet
					case ftlog.ComponentOS:
						got = os
					}
					if got.String() != want.GitTagName.String() {
						t.Errorf("got %v, want %v", got, want)
					}
				}
			}
		})
	}
}

func getBinary(_ context.Context, release ftlog.FirmwareRelease) ([]byte, error) {
	return []byte(release.GitTagName.String()), nil
}

func mustNewVerifierSigner(t *testing.T) (note.Verifier, note.Signer) {
	t.Helper()
	v, err := note.NewVerifier(testVkey)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	s, err := note.NewSigner(testSkey)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	return v, s
}

// addReleasesToLog sequences and integrates the provided releases into the log based on
// the given storage.
func addReleasesToLog(ctx context.Context, t *testing.T, ms *testonly.MemStorage, origin string, lv note.Verifier, ls note.Signer, releases []ftlog.FirmwareRelease) {
	t.Helper()
	cpRaw, err := ms.Fetcher()(ctx, layout.CheckpointPath)
	if err != nil {
		t.Fatalf("Fetch checkpoint: %v", err)
	}
	cp, _, _, err := log.ParseCheckpoint(cpRaw, origin, lv)
	if err != nil {
		t.Fatalf("ParseCheckpoint: %v", err)
	}
	for _, r := range releases {
		l, err := json.MarshalIndent(r, "", " ")
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		lh := rfc6962.DefaultHasher.HashLeaf(l)
		if _, err := ms.Sequence(ctx, lh, l); err != nil {
			t.Fatalf("Sequence: %v", err)
		}
	}
	cpNew, err := slog.Integrate(ctx, cp.Size, ms, rfc6962.DefaultHasher)
	if err != nil {
		t.Fatalf("Integrate: %v", err)
	}
	cpNew.Origin = testOrigin
	cps, err := note.Sign(&note.Note{Text: string(cpNew.Marshal())}, ls)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	if err := ms.WriteCheckpoint(ctx, cps); err != nil {
		t.Fatalf("WriteCheckpoint: %v", err)
	}
}

// initLog initialises the provided log storage to a valid empty state.
func initLog(ctx context.Context, t *testing.T, s slog.Storage) {
	cp := fmtlog.Checkpoint{
		Origin: testOrigin,
	}
	cpNote := note.Note{Text: string(cp.Marshal())}
	signer, err := note.NewSigner(testSkey)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	cpNoteSigned, err := note.Sign(&cpNote, signer)
	if err != nil {
		t.Fatalf("Failed to sign Checkpoint: %q", err)
	}
	if err := s.WriteCheckpoint(ctx, cpNoteSigned); err != nil {
		t.Fatalf("Failed to store new log checkpoint: %q", err)
	}
}
