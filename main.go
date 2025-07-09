// Copyright (c) HashiCorp, Inc.
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"flag"
	"log"

	"github.com/step-security/terraform-provider-stepsecurity/internal/provider"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	// these will be set by the goreleaser configuration
	// to appropriate values for the compiled binary.
	version string = "dev"
)

func main() {
	var debug bool

	flag.BoolVar(&debug, "debug", false, "set to true to run the provider with support for debuggers like delve")
	flag.Parse()

	opts := providerserver.ServeOpts{
		Address: "registry.terraform.io/step-security/stepsecurity",
		Debug:   debug,
	}

	tflog.Info(context.Background(), "Starting StepSecurity provider", map[string]any{"version": version})

	err := providerserver.Serve(context.Background(), provider.New(version), opts)
	if err != nil {
		tflog.Error(context.Background(), "Failed to start StepSecurity provider", map[string]any{"error": err.Error()})
		log.Fatal(err.Error())
	}
}
