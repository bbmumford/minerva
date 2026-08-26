/*
 * Copyright (c) 2026 HSTLES / ORBTR Pty Ltd. All Rights Reserved.
 * Queries: licensing@hstles.com
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
