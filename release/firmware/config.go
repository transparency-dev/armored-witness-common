// Copyright 2022 The Armored Witness Boot authors. All Rights Reserved.
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
	"encoding/gob"
	"fmt"
)

const (
	ConfigMaxLength = 40960

	// Block size in bytes of the MMC device on the armored witness.
	MMCBlockSize = 512

	// BootloaderBlock defines the location of the first block of the bootloader on MMC.
	BootloaderBlock  = 0x2
	BootloaderOffset = BootloaderBlock * MMCBlockSize
	// OSBlock defines the location of the first block of the TrustedOS on MMC.
	OSBlock  = 0x5000
	OSOffset = OSBlock * MMCBlockSize

	// AppletBlock defines the location of the first block of the TrustedApplet on MMC.
	AppletBlock  = 0x200000
	AppletOffset = AppletBlock * MMCBlockSize
)

// Config represents the armored-witness-boot configuration.
type Config struct {
	// Offset is the MMC/SD card offset in bytes to an ELF unikernel image (e.g. TamaGo).
	Offset int64
	// Size is the unikernel length in bytes.
	Size int64
	// Signatures are the unikernel signify/minisign signatures.
	Signatures [][]byte
	// Bundle contains firmware transparency artefacts relating to the firmware this config
	// references.
	Bundle Bundle
}

// Encode serializes the configuration.
func (c *Config) Encode() ([]byte, error) {
	buf := new(bytes.Buffer)
	err := gob.NewEncoder(buf).Encode(c)

	if l := buf.Len(); l > ConfigMaxLength {
		return buf.Bytes(), fmt.Errorf("config too large (%d > %d)", l, ConfigMaxLength)
	}

	return buf.Bytes(), err
}

// Decode deserializes the configuration.
func (c *Config) Decode(buf []byte) (err error) {
	// TODO: Go encoding/gob makes the following commitment:
	//
	// "Any future changes to the package will endeavor to maintain
	// compatibility with streams encoded using previous versions"
	//
	// Do we treat this as sufficient considering that we will throw away
	// the secure boot signing keys for this firmware?
	return gob.NewDecoder(bytes.NewBuffer(buf)).Decode(c)
}
