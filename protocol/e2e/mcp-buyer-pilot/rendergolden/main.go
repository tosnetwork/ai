// Command rendergolden prints the confirmer's screen for one presentation,
// read as JSON from standard input, with the default sensitive-name
// patterns. The pilot's confirmation policy tests
// (harness/test_confirm_policy.py) parse its output, so the policy is held
// to the real renderer rather than to a copy of its layout.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/tosnetwork/ai/protocol/pkg/buyeragent"
	"github.com/tosnetwork/ai/protocol/pkg/buyerconfirm"
)

func main() {
	raw, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
	if err != nil {
		fmt.Fprintln(os.Stderr, "rendergolden:", err)
		os.Exit(2)
	}
	var presentation buyeragent.Presentation
	if err := json.Unmarshal(raw, &presentation); err != nil {
		fmt.Fprintln(os.Stderr, "rendergolden:", err)
		os.Exit(2)
	}
	fmt.Print(buyerconfirm.Render(presentation, buyerconfirm.DefaultSensitive))
}
