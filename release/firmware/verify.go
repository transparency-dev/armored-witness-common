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

package firmware

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"

	"github.com/transparency-dev/armored-witness-common/release/firmware/ftlog"
	"github.com/transparency-dev/formats/log"
	"github.com/transparency-dev/merkle/proof"
	"github.com/transparency-dev/merkle/rfc6962"
	"golang.org/x/mod/sumdb/note"
)

type BundleVerifier struct {
	// LogOrigin identifies the expected FT log for manifests to be submitted to.
	LogOrigin string
	// LogVerifier can verify signatures from the expected FT log.
	LogVerifer note.Verifier
	// ManifestVerifiers is a list of verifiers to use when verifying signatures over manifests.
	// ALL verifiers are expected to succeed - i.e. there must be a matching signature present
	// on the manifest for every verifier in this list.
	ManifestVerifiers []note.Verifier
}

// Verify checks the firmware bundle and returns an error if invalid, or nil
// if the firmware is safe to install.
func (v *BundleVerifier) Verify(b Bundle) error {
	// TODO(mhutchinson): check some witness signatures in addition to the log signature.
	cp, _, _, err := log.ParseCheckpoint(b.Checkpoint, v.LogOrigin, v.LogVerifer)
	if err != nil {
		return fmt.Errorf("ParseCheckpoint(): %v", err)
	}

	n, err := note.Open(b.Manifest, note.VerifierList(v.ManifestVerifiers...))
	if err != nil {
		return fmt.Errorf("note.Open(): %v", err)
	}
	if got, want := len(n.Sigs), len(v.ManifestVerifiers); got != want {
		return fmt.Errorf("got %d verified signatures, want %d", got, want)
	}
	manifest := ftlog.FirmwareRelease{}
	if err := json.Unmarshal([]byte(n.Text), &manifest); err != nil {
		return fmt.Errorf("Unmarshal(): %v", err)
	}

	leafHash := rfc6962.DefaultHasher.HashLeaf(b.Manifest)
	if err := proof.VerifyInclusion(rfc6962.DefaultHasher, b.Index, cp.Size, leafHash, b.InclusionProof, cp.Hash); err != nil {
		return fmt.Errorf("inclusion proof verification failed: %v", err)
	}

	h := sha256.Sum256(b.Firmware)
	if manifestHash, calculatedHash := manifest.FirmwareDigestSha256, h[:]; !bytes.Equal(manifestHash, calculatedHash) {
		return fmt.Errorf("firmware hash mismatch: manifest says %x but firmware bytes hash to %x", manifestHash, calculatedHash)
	}
	return nil
}
