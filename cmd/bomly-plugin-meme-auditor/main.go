// Command bomly-plugin-meme-auditor serves the meme dependency auditor as a
// managed Bomly plugin over the HashiCorp go-plugin gRPC transport. The
// binary is launched and supervised by Bomly; it is not meant to be run by
// hand.
package main

import (
	"github.com/bomly-dev/bomly-plugin-meme-auditor/plugin"

	"github.com/bomly-dev/bomly-sdk/runtime"
)

func main() { runtime.ServeModule(plugin.Module()) }
