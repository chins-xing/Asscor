package main

import (
	"fmt"
	"os"

	"github.com/chins-xing/asscor/extensions/logcollector"
)

func main() {
	if err := logcollector.RunChild(); err != nil {
		fmt.Fprintln(os.Stderr, "logcollector-mod:", err)
		os.Exit(1)
	}
}
