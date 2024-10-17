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
	"errors"
	"fmt"
	"sync"

	"github.com/coreos/go-semver/semver"
	"github.com/transparency-dev/armored-witness-common/release/firmware"
	"github.com/transparency-dev/armored-witness-common/release/firmware/ftlog"
	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"golang.org/x/mod/sumdb/note"
	"k8s.io/klog/v2"

	"github.com/transparency-dev/serverless-log/client"
)

// BinaryFetcher returns the firmware image and HAB signature (if applicable) corresponding to the given release.
type BinaryFetcher func(context.Context, ftlog.FirmwareRelease) ([]byte, []byte, error)

// FetcherOpts holds configuration options for creating a new Fetcher.
type FetcherOpts struct {
	// BinaryFetcher should be able to return binaries referenced from entries in the log.
	BinaryFetcher BinaryFetcher
	// LogFetcher should be able to communicate with the target FT log.
	LogFetcher client.Fetcher
	// LogOrigin is the Origin string associated with the target FT log.
	LogOrigin string
	// LogVerifier is used to verify checkpoint signatures from the target FT log.
	LogVerifier note.Verifier

	// AppletVerifier is used to verify signatures on applet manifests.
	AppletVerifier note.Verifier
	// BootVerifier is used to verify signatures on bootloader manifests.
	BootVerifier note.Verifier
	// OSVerifiers are used to verify signatures on OS manifests.
	OSVerifiers [2]note.Verifier
	// RecoveryVerifier is used to verify signatures on recovery manifests.
	RecoveryVerifier note.Verifier

	// HABTarget, if set, will require that manifest HAB.Target values must match for
	// Bootloader and Recovery entries.
	// This is to help ensure that HAB-fused devices get boot firmware with the correct
	// signature.
	HABTarget string

	// PreviousCheckpointRaw is optional and should contain the raw bytes of the checkpoint
	// used during the last firmware update.
	// Leaving this unset will cause the Fetcher to consider all entries in the log, rather than
	// just those added since the last update.
	PreviousCheckpointRaw []byte
}

// BinaryPath returns the relative path within a bucket for the binary referenced by the manifest.
func BinaryPath(fr ftlog.FirmwareRelease) (string, error) {
	if len(fr.Output.FirmwareDigestSha256) == 0 {
		return "", errors.New("firmware digest unset")
	}
	return fmt.Sprintf("%064x", fr.Output.FirmwareDigestSha256), nil
}

// HABSignaturePath returns the relative path within a bucket for the HAB signature referenced by the manifest.
func HABSignaturePath(fr ftlog.FirmwareRelease) (string, error) {
	if fr.HAB == nil {
		return "", errors.New("no HAB information in manifest")
	}
	if len(fr.HAB.SignatureDigestSha256) == 0 {
		return "", errors.New("HAB signature digest unset")
	}
	return fmt.Sprintf("%064x", fr.HAB.SignatureDigestSha256), nil
}

// NewFetcher returns an implementation of a Remote that uses the given log client to
// fetch release data from the log.
func NewFetcher(ctx context.Context, opts FetcherOpts) (*Fetcher, error) {
	ls, err := client.NewLogStateTracker(
		ctx,
		opts.LogFetcher,
		rfc6962.DefaultHasher,
		opts.PreviousCheckpointRaw,
		opts.LogVerifier,
		opts.LogOrigin,
		client.UnilateralConsensus(opts.LogFetcher))
	if err != nil {
		return nil, fmt.Errorf("NewLogStateTracker: %v", err)
	}

	f := &Fetcher{
		logFetcher:  opts.LogFetcher,
		logVerifier: opts.LogVerifier,
		logOrigin:   opts.LogOrigin,
		logState:    ls,
		binFetcher:  opts.BinaryFetcher,
		habTarget:   opts.HABTarget,
		scanFrom:    0,
	}
	f.manifestVerifiers = make(map[string][]note.Verifier)
	if v := opts.AppletVerifier; v != nil {
		f.manifestVerifiers[ftlog.ComponentApplet] = []note.Verifier{v}
	}
	if v := opts.BootVerifier; v != nil {
		f.manifestVerifiers[ftlog.ComponentBoot] = []note.Verifier{v}
	}
	if v := opts.OSVerifiers; len(v) > 0 {
		f.manifestVerifiers[ftlog.ComponentOS] = v[:]
	}
	if v := opts.RecoveryVerifier; v != nil {
		f.manifestVerifiers[ftlog.ComponentRecovery] = []note.Verifier{v}
	}
	// IFF we were provided the previously used checkpoint, we'll override the
	// log index at which we'll start scanning.
	if opts.PreviousCheckpointRaw != nil {
		// Note that we cannot always just take the latest consistent size from the
		// LogStateTracker here: if no previous checkpoint was provided to it,
		// LogStateTracker will fetch the latest available checkpoint from the target
		// log during initialisation, and our scanFrom index will be incorrect.
		f.scanFrom = ls.LatestConsistent.Size
	}
	return f, nil
}

type Fetcher struct {
	logFetcher  client.Fetcher
	logOrigin   string
	logVerifier note.Verifier
	habTarget   string

	binFetcher BinaryFetcher

	manifestVerifiers map[string][]note.Verifier

	mu             sync.Mutex
	latestOS       *firmwareRelease
	latestApplet   *firmwareRelease
	latestBoot     *firmwareRelease
	latestRecovery *firmwareRelease
	logState       client.LogStateTracker
	scanFrom       uint64
}

func (f *Fetcher) GetLatestVersions(_ context.Context) (os semver.Version, applet semver.Version, err error) {
	if f.latestOS == nil || f.latestApplet == nil {
		return semver.Version{}, semver.Version{}, errors.New("no versions of OS or applet found in log")
	}
	return f.latestOS.manifest.Git.TagName, f.latestApplet.manifest.Git.TagName, nil
}

func (f *Fetcher) GetOS(ctx context.Context) (firmware.Bundle, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.latestOS == nil {
		return firmware.Bundle{}, errors.New("no latest OS available")
	}
	if f.latestOS.bundle.Firmware == nil {
		binary, _, err := f.binFetcher(ctx, f.latestOS.manifest)
		if err != nil {
			return firmware.Bundle{}, fmt.Errorf("BinaryFetcher(): %v", err)
		}
		f.latestOS.bundle.Firmware = binary
	}
	return *f.latestOS.bundle, nil
}

func (f *Fetcher) GetApplet(ctx context.Context) (firmware.Bundle, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.latestApplet == nil {
		return firmware.Bundle{}, errors.New("no latest applet available")
	}
	if f.latestApplet.bundle.Firmware == nil {
		binary, _, err := f.binFetcher(ctx, f.latestApplet.manifest)
		if err != nil {
			return firmware.Bundle{}, fmt.Errorf("BinaryFetcher(): %v", err)
		}
		f.latestApplet.bundle.Firmware = binary
	}
	return *f.latestApplet.bundle, nil
}

func (f *Fetcher) GetBoot(ctx context.Context) (firmware.Bundle, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.latestBoot == nil {
		return firmware.Bundle{}, errors.New("no latest boot available")
	}
	if f.latestBoot.bundle.Firmware == nil {
		binary, habSig, err := f.binFetcher(ctx, f.latestBoot.manifest)
		if err != nil {
			return firmware.Bundle{}, fmt.Errorf("BinaryFetcher(): %v", err)
		}
		f.latestBoot.bundle.Firmware = binary
		f.latestBoot.bundle.HABSignature = habSig
	}
	return *f.latestBoot.bundle, nil
}

func (f *Fetcher) GetRecovery(ctx context.Context) (firmware.Bundle, error) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if f.latestRecovery == nil {
		return firmware.Bundle{}, errors.New("no latest recovery available")
	}
	if f.latestRecovery.bundle.Firmware == nil {
		binary, habSig, err := f.binFetcher(ctx, f.latestRecovery.manifest)
		if err != nil {
			return firmware.Bundle{}, fmt.Errorf("BinaryFetcher(): %v", err)
		}
		f.latestRecovery.bundle.Firmware = binary
		f.latestRecovery.bundle.HABSignature = habSig
	}
	return *f.latestRecovery.bundle, nil
}

// Scan gets the latest checkpoint from the log and updates the fetcher's state
// to reflect the latest OS and Applet available in the log.
func (f *Fetcher) Scan(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()

	session, err := f.NewSession(ctx)
	if err != nil {
		return err
	}

	if session.cp.Size <= f.scanFrom {
		return nil
	}

	for i := f.scanFrom; i < session.cp.Size; i++ {
		bundle, manifest, err := session.Fetch(ctx, i)
		if err != nil {
			klog.Errorf("Failed to verifiably fetch leaf at index %d: %v", i, err)
			continue
		}
		isHABComponent := manifest.Component == ftlog.ComponentBoot || manifest.Component == ftlog.ComponentRecovery
		if isHABComponent && f.habTarget != "" && (manifest.HAB == nil || f.habTarget != manifest.HAB.Target) {
			mt := "nil"
			if manifest.HAB != nil {
				mt = manifest.HAB.Target
			}
			klog.V(1).Infof("Skipping leaf %d as manifest hab target %q != required target %q", i, mt, f.habTarget)
			continue
		}
		switch manifest.Component {
		case ftlog.ComponentOS:
			f.latestOS = highestRelease(f.latestOS, &firmwareRelease{bundle: bundle, manifest: *manifest})
		case ftlog.ComponentApplet:
			f.latestApplet = highestRelease(f.latestApplet, &firmwareRelease{bundle: bundle, manifest: *manifest})
		case ftlog.ComponentBoot:
			f.latestBoot = highestRelease(f.latestBoot, &firmwareRelease{bundle: bundle, manifest: *manifest})
		case ftlog.ComponentRecovery:
			f.latestRecovery = highestRelease(f.latestRecovery, &firmwareRelease{bundle: bundle, manifest: *manifest})
		default:
			klog.Warningf("unknown component type in log: %q", manifest.Component)
		}
	}
	f.scanFrom = session.cp.Size
	return nil
}

func (f *Fetcher) NewSession(ctx context.Context) (FetchSession, error) {
	_, _, cpRaw, err := f.logState.Update(ctx)
	if err != nil {
		return FetchSession{}, fmt.Errorf("logState.Update(): %v", err)
	}
	to, _, _, err := log.ParseCheckpoint(cpRaw, f.logOrigin, f.logVerifier)
	if err != nil {
		return FetchSession{}, fmt.Errorf("ParseCheckpoint(): %v", err)
	}

	return FetchSession{
		cpRaw:             cpRaw,
		cp:                to,
		logFetcher:        f.logFetcher,
		logState:          f.logState,
		manifestVerifiers: f.manifestVerifiers,
	}, nil
}

type FetchSession struct {
	cpRaw             []byte
	cp                *log.Checkpoint
	logFetcher        client.Fetcher
	logState          client.LogStateTracker
	manifestVerifiers map[string][]note.Verifier
}

func (s FetchSession) Fetch(ctx context.Context, i uint64) (*firmware.Bundle, *ftlog.FirmwareRelease, error) {
	leaf, err := client.GetLeaf(ctx, s.logFetcher, i)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get log leaf %d: %v", i, err)
	}
	incP, err := s.logState.ProofBuilder.InclusionProof(ctx, i)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get inclusion proof for leaf %d: %v", i, err)
	}
	if err := proof.VerifyInclusion(s.logState.Hasher, i, s.cp.Size, s.logState.Hasher.HashLeaf(leaf), incP, s.cp.Hash); err != nil {
		return nil, nil, fmt.Errorf("invalid inclusion proof for leaf %d: %v", i, err)
	}
	manifest, err := parseLeaf(leaf, s.manifestVerifiers)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse leaf at %d: %v", i, err)
	}
	bundle := &firmware.Bundle{
		Checkpoint:     s.cpRaw,
		Index:          i,
		InclusionProof: incP,
		Manifest:       leaf,
		Firmware:       nil, // This will be downloaded on demand
	}
	return bundle, &manifest, nil
}

// highestRelease returns the "higher" of the two releases passed in according to SemVer rules.
//
// According to the SemVer2.0 spec, equal revisions have no precedence defined.
// In general this won't be an issue; production releases will always be tagged appropriately,
// and there should never be two different releases with the same semver for a given component,
// however, during development, this may not hold.
// To tighten the definition of precedence, we'll use the fact that logs define ordering
// and say that "later" entries take precedence over "earlier" entries with the same version
// numbering.
func highestRelease(current *firmwareRelease, candidate *firmwareRelease) *firmwareRelease {
	if current == nil ||
		current.manifest.Git.TagName.LessThan(candidate.manifest.Git.TagName) ||
		current.manifest.Git.TagName.Equal(candidate.manifest.Git.TagName) {
		return candidate
	}
	return current
}

func parseLeaf(leaf []byte, verifiers map[string][]note.Verifier) (ftlog.FirmwareRelease, error) {
	var n *note.Note
	var err error
	var expectedComponent string

	klog.V(2).Infof(string(leaf))

	for k, v := range verifiers {
		if n, err = note.Open(leaf, note.VerifierList(v...)); err != nil {
			klog.V(1).Info(err)
			continue
		}
		// We've opened the note successfully, but check that we got as many signatures as
		// expected - this is currently only really a concern for the OS which is expected to
		// be signed by two parties.
		if lv, ls := len(v), len(n.Sigs); lv != ls {
			return ftlog.FirmwareRelease{}, fmt.Errorf("expected %d sigs, got %d", lv, ls)
		}
		expectedComponent = k

		r := ftlog.FirmwareRelease{}
		if err := json.Unmarshal([]byte(n.Text), &r); err != nil {
			return r, fmt.Errorf("failed to unmarshal manifest body: %v", err)
		}
		if got := r.Component; got != expectedComponent {
			return ftlog.FirmwareRelease{}, fmt.Errorf("unexpected component type %q verified by %q signature", got, expectedComponent)
		}

		return r, nil

	}

	return ftlog.FirmwareRelease{}, errors.New("no recognised signatures")
}

type firmwareRelease struct {
	bundle   *firmware.Bundle
	manifest ftlog.FirmwareRelease
}
