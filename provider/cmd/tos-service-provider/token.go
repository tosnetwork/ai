package main

import (
	"context"
	"encoding/json"
	"flag"

	"github.com/tosnetwork/ai/provider/pkg/servicebridge"
)

// The direct operator path has the same preview and exact-digest gate as MCP.
func runToken(ctx context.Context, set *flag.FlagSet, args []string, std streams) error {
	var configPath, inputPath, digest, inspect, actor string
	var yes bool
	set.StringVar(&inspect, "inspect", "", "status, offer or export-offer; read only")
	set.StringVar(&actor, "actor", "", "configured token actor for inspection")
	set.StringVar(&configPath, "rail-config", "", "owner-private provider configuration")
	set.StringVar(&configPath, "config", "", "owner-private provider configuration")
	set.StringVar(&inputPath, "input", "", "owner-private TokenActionInput JSON; reuse the same idempotency key after interruption")
	set.StringVar(&digest, "confirmed-digest", "", "exact digest from the reviewed preview")
	set.BoolVar(&yes, "yes", false, "apply the exact reviewed preview")
	if done, err := parse(set, args, "rail-config"); done || err != nil {
		return err
	}
	if set.NArg() != 0 || configPath == "" || inputPath == "" && inspect == "" {
		return usagef("token requires --config and --input")
	}
	c, err := servicebridge.LoadNodeConfig(configPath)
	if err != nil {
		return err
	}
	if inspect != "" {
		if inputPath != "" || yes || digest != "" || actor == "" {
			return usagef("inspection requires --actor and no action inputs")
		}
		var result any
		switch inspect {
		case "status":
			result, err = servicebridge.ReadTokenStatus(ctx, c, actor, servicebridge.TokenEnv{})
		case "offer":
			result, err = servicebridge.TokenOffer(ctx, c, actor, servicebridge.TokenEnv{})
		case "export-offer":
			var raw []byte
			raw, err = servicebridge.ExportTokenOffer(ctx, c, actor, servicebridge.TokenEnv{})
			if err == nil {
				_, err = std.out.Write(raw)
			}
			return err
		default:
			return usagef("unknown token inspection")
		}
		if err != nil {
			return err
		}
		return json.NewEncoder(std.out).Encode(result)
	}
	in, err := servicebridge.ReadTokenActionInput(inputPath)
	if err != nil {
		return err
	}
	r, err := servicebridge.RunTokenAction(ctx, c, in, yes, digest, servicebridge.TokenEnv{})
	if r != nil {
		if e := json.NewEncoder(std.out).Encode(r); e != nil {
			return e
		}
	}
	return err
}
