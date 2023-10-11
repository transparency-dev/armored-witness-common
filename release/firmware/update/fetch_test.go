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
	testOrigin       = "testlog"
	testVkey         = "ArmoredWitnessFirmwareLog+3e6f9306+ARjETaImkiqXZCH5pk1XtfX0tHgFhi1qGIxQqT6231S1"
	testSkey         = "PRIVATE+KEY+ArmoredWitnessFirmwareLog+3e6f9306+AYJIjPyyT5wKmBQ8duU8Bwl2ZSslUmrMgwdTUChHKEag"
	testAppletVkey   = "test-applet+290af40f+Af0AiAktGwImYbgFA9UrczRbYBaJbdZzn5A2ToTOkqxV"
	testAppletSkey   = "PRIVATE+KEY+test-applet+290af40f+ATJe9X6imT+eg+NFDPcjHGl9bqEsN+NIflq4lRydqPKW"
	testBootVkey     = "test-boot+44991abe+AUjHQ4wNywnc2WLBdBb+tIG0PPgDRyUGEsW2MwaHIPpF"
	testBootSkey     = "PRIVATE+KEY+test-boot+44991abe+AT51PcaJZhqcONnHuQo3Qa6cN7t+Al8Sl7+1kZIfbGXw"
	testOSVkey1      = "test-os-1+9395589a+AYlQ0SeQx8tVtQZkIJxU7OKmv8rspXRiRc4hVO/bq1xV"
	testOSSkey1      = "PRIVATE+KEY+test-os-1+9395589a+AXPnLROuLHRm7Qlj8HNU9tVfX6dinmdaVVeGVFPvQg0k"
	testOSVkey2      = "test-os-2+102291d1+AV91Bykl/mok7XNiC8XCDn+6bScvzttbqo2ru0Xdocj5"
	testOSSkey2      = "PRIVATE+KEY+test-os-2+102291d1+AdvxU28+7keAQNjlXuf+M1FjUXLKi+2n9f8MrKWFJgiR"
	testRecoveryVkey = "test-recovery+e1d7acb6+AS+hiEKKtij7apEWQQicV76hBPAlYIVnxmuoeRonKFQZ"
	testRecoverySkey = "PRIVATE+KEY+test-recovery+e1d7acb6+AYebvQ5b1GxgnuTGc+p7CgKdEx2WUPk4ieAgObFq4wqW"
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
	lv, ls := mustNewVerifierSigner(t, testVkey, testSkey)
	av, as := mustNewVerifierSigner(t, testAppletVkey, testAppletSkey)
	bv, bs := mustNewVerifierSigner(t, testBootVkey, testBootSkey)
	ov1, os1 := mustNewVerifierSigner(t, testOSVkey1, testOSSkey1)
	ov2, os2 := mustNewVerifierSigner(t, testOSVkey2, testOSSkey2)
	rv, rs := mustNewVerifierSigner(t, testRecoveryVkey, testRecoverySkey)
	relSigners := map[string][]note.Signer{
		ftlog.ComponentApplet:   {as},
		ftlog.ComponentBoot:     {bs},
		ftlog.ComponentOS:       {os1, os2},
		ftlog.ComponentRecovery: {rs},
	}

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
					{Component: ftlog.ComponentBoot, GitTagName: *semver.New("1.3.1")},
					{Component: ftlog.ComponentRecovery, GitTagName: *semver.New("1.1.1")},
				},
				{
					{Component: ftlog.ComponentOS, GitTagName: *semver.New("1.2.1")},
					{Component: ftlog.ComponentApplet, GitTagName: *semver.New("1.3.1")},
					{Component: ftlog.ComponentBoot, GitTagName: *semver.New("1.3.1")},
					{Component: ftlog.ComponentRecovery, GitTagName: *semver.New("1.1.1")},
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
					{Component: ftlog.ComponentBoot, GitTagName: *semver.New("1.3.1")},
					{Component: ftlog.ComponentRecovery, GitTagName: *semver.New("1.1.1")},
				},
			},
		}, {
			desc: "Finds latest within multiple revs",
			releases: [][]ftlog.FirmwareRelease{
				{
					{Component: ftlog.ComponentOS, GitTagName: *semver.New("1.0.1")},
					{Component: ftlog.ComponentApplet, GitTagName: *semver.New("1.1.1")},
					{Component: ftlog.ComponentBoot, GitTagName: *semver.New("1.3.1")},
					{Component: ftlog.ComponentRecovery, GitTagName: *semver.New("1.1.1")},
					{Component: ftlog.ComponentOS, GitTagName: *semver.New("1.0.2")},
					{Component: ftlog.ComponentApplet, GitTagName: *semver.New("2.0.1")},
					{Component: ftlog.ComponentBoot, GitTagName: *semver.New("1.7.1")},
					{Component: ftlog.ComponentRecovery, GitTagName: *semver.New("1.8.1")},
				},
			},
			want: [][]ftlog.FirmwareRelease{
				{
					{Component: ftlog.ComponentOS, GitTagName: *semver.New("1.0.2")},
					{Component: ftlog.ComponentApplet, GitTagName: *semver.New("2.0.1")},
					{Component: ftlog.ComponentBoot, GitTagName: *semver.New("1.7.1")},
					{Component: ftlog.ComponentRecovery, GitTagName: *semver.New("1.8.1")},
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

				addReleasesToLog(ctx, t, ms, testOrigin, lv, ls, relSigners, test.releases[i])

				f, err := NewFetcher(ctx, FetcherOpts{
					BinaryFetcher:         getBinary,
					LogFetcher:            ms.Fetcher(),
					LogOrigin:             testOrigin,
					LogVerifier:           lv,
					AppletVerifier:        av,
					BootVerifier:          bv,
					OSVerifiers:           [2]note.Verifier{ov1, ov2},
					RecoveryVerifier:      rv,
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
						if _, err = f.GetApplet(ctx); err != nil {
							t.Fatalf("GetApplet: %v", err)
						}
					case ftlog.ComponentBoot:
						if _, err = f.GetBoot(ctx); err != nil {
							t.Fatalf("GetBoot: %v", err)
						}
						got = f.latestBoot.manifest.GitTagName
					case ftlog.ComponentOS:
						got = os
						if _, err = f.GetOS(ctx); err != nil {
							t.Fatalf("GetOS: %v", err)
						}
					case ftlog.ComponentRecovery:
						if _, err = f.GetRecovery(ctx); err != nil {
							t.Fatalf("GetRecovery: %v", err)
						}
						got = f.latestRecovery.manifest.GitTagName
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

func mustNewVerifierSigner(t *testing.T, vk, sk string) (note.Verifier, note.Signer) {
	t.Helper()
	v, err := note.NewVerifier(vk)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	s, err := note.NewSigner(sk)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	return v, s
}

// addReleasesToLog sequences and integrates the provided releases into the log based on
// the given storage.
func addReleasesToLog(ctx context.Context, t *testing.T, ms *testonly.MemStorage, origin string, lv note.Verifier, ls note.Signer, rs map[string][]note.Signer, releases []ftlog.FirmwareRelease) {
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
		j, err := json.MarshalIndent(r, "", " ")
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		l, err := note.Sign(&note.Note{Text: string(j) + "\n"}, rs[r.Component]...)
		if err != nil {
			t.Fatalf("Sign: %v", err)
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
