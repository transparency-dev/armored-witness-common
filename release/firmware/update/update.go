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

// Package update provides functionality for fetching updates, verifying
// them, and installing them onto the armory device.
package update

import (
	"context"
	"fmt"

	"github.com/coreos/go-semver/semver"
	"github.com/transparency-dev/armored-witness-common/release/firmware"
	"k8s.io/klog/v2"
)

// Local allows access to query the firmware installed on this device and
// operations to install new versions of the firmware.
type Local interface {
	// GetInstalledVersions returns the semantic versions of the OS and Applet
	// installed on this device. These will be the same versions that are
	// currently running.
	GetInstalledVersions() (os, applet semver.Version, err error)

	// InstallOS updates the OS to the version contained in the firmware bundle.
	// If the update is successful, the RPC will not return.
	InstallOS(firmware.Bundle) error

	// InstallApplet updates the Applet to the version contained in the firmware bundle.
	// If the update is successful, the RPC will not return.
	InstallApplet(firmware.Bundle) error
}

// A Remote represents the connection to the Internet and allows access to
// query and fetch new versions of firmware.
type Remote interface {
	// GetLatestVersions returns the latest available versions of the OS and Applet.
	GetLatestVersions(context.Context) (os, applet semver.Version, err error)
	// GetOS fetches the operating system executable and associated metadata.
	GetOS(context.Context) (firmware.Bundle, error)
	// GetApplet fetches the applet executable and associated metadata.
	GetApplet(context.Context) (firmware.Bundle, error)
}

// A FirmwareVerifier checks that the given Bundle passes installation policy.
type FirmwareVerifier interface {
	// Verify checks the firmware bundle and returns an error if invalid, or nil
	// if the firmware is safe to install.
	Verify(firmware.Bundle) error
}

// NewUpdater returns an Updater that uses local to query/update the device, remote to
// query/fetch new updates, and verifier to ensure that downloaded content passes installation
// policy.
func NewUpdater(local Local, remote Remote, verifier FirmwareVerifier) (*Updater, error) {
	osVer, appVer, err := local.GetInstalledVersions()
	if err != nil {
		return nil, fmt.Errorf("failed to determine installed versions: %v", err)
	}
	return &Updater{
		local:    local,
		remote:   remote,
		verifier: verifier,
		osVer:    osVer,
		appVer:   appVer,
	}, nil
}

// Updater should be periodically invoked via Update to check for and install firmware
// udpates for the OS and applet.
type Updater struct {
	local         Local
	remote        Remote
	verifier      FirmwareVerifier
	osVer, appVer semver.Version
}

// Update checks whether newer versions of installed firmware are available, and if so
// it fetches, verifies, and installs the firmware. If any changes are made to the
// firmware on disk then this function will not return because a reboot will be scheduled.
// This function is designed to be called periodically by a single thread. It is not
// thread safe.
func (u Updater) Update(ctx context.Context) error {
	osVer, appVer, err := u.remote.GetLatestVersions(ctx)
	if err != nil {
		return fmt.Errorf("failed to get latest versions: %v", err)
	}

	if u.osVer.LessThan(osVer) {
		klog.Infof("Upgrading OS from %q to %q", u.osVer, osVer)
		bundle, err := u.remote.GetOS(ctx)
		if err != nil {
			return fmt.Errorf("failed to fetch OS firmware: %v", err)
		}
		if err := u.verifier.Verify(bundle); err != nil {
			return fmt.Errorf("verification of OS firmware bundle failed: %v", err)
		}
		if err := u.local.InstallOS(bundle); err != nil {
			return fmt.Errorf("failed to install OS firmware: %v", err)
		}
	}
	if u.appVer.LessThan(appVer) {
		klog.Infof("Upgrading applet from %q to %q", u.appVer, appVer)
		bundle, err := u.remote.GetApplet(ctx)
		if err != nil {
			return fmt.Errorf("failed to fetch applet firmware: %v", err)
		}
		if err := u.verifier.Verify(bundle); err != nil {
			return fmt.Errorf("verification of applet firmware bundle failed: %v", err)
		}
		if err := u.local.InstallApplet(bundle); err != nil {
			return fmt.Errorf("failed to install applet firmware: %v", err)
		}
	}
	klog.V(1).Infof("Self-update: no updates applied (os: %v applet: %v)", u.osVer, u.appVer)
	return nil
}
