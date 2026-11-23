/*
 * Copyright (c) 2026 Brandon Miller-Mumford.
 * Licensed under the MIT License; see LICENSE.
 */
package messaging

import (
	"fmt"
	"os"
)

var debugOn = os.Getenv("MINERVA_MESSAGING_DEBUG") != ""

func debugf(format string, args ...any) {
	if debugOn {
		fmt.Fprintf(os.Stderr, "[mnrv-msg] "+format+"\n", args...)
	}
}
