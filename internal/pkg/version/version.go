// Copyright (c) 2023 NTT Communications Corporation
//
// This software is released under the MIT License.
// see https://github.com/nttcom/fluvia/blob/main/LICENSE

package version

import "fmt"

const MAJOR uint = 1
const MINOR uint = 2
const PATCH uint = 1

func Version() string {
	return fmt.Sprintf("%d.%d.%d", MAJOR, MINOR, PATCH)
}
