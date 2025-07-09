# Terraform Provider for StepSecurity

The StepSecurity provider allows Terraform to manage StepSecurity resources, enabling you to secure your GitHub Actions workflows and repositories through infrastructure as code.

## Quick Links

- [Provider Documentation](https://registry.terraform.io/providers/step-security/stepsecurity/latest/docs)
- [StepSecurity Website](https://www.stepsecurity.io)
- [GitHub Issues](https://github.com/step-security/terraform-provider-stepsecurity/issues)

## Requirements

- [Terraform](https://www.terraform.io/downloads.html) >= 1.0
- [Go](https://golang.org/doc/install) >= 1.24 (for development)

## Using the Provider

### Installation

The provider will be installed automatically when you run `terraform init` if you include it in your configuration.

```hcl
terraform {
  required_providers {
    stepsecurity = {
      source  = "step-security/stepsecurity"
      version = "~> 1.0"
    }
  }
}
```

### Authentication

The provider requires authentication with the StepSecurity API. You can configure this in several ways:

#### Environment Variables (Recommended)

```bash
export STEP_SECURITY_API_KEY="your-api-key"
export STEP_SECURITY_CUSTOMER="your-customer-name"
export STEP_SECURITY_API_BASE_URL="api-base-url"  # Optional
```

#### Provider Configuration

```hcl
provider "stepsecurity" {
  api_key      = "your-api-key"
  customer     = "your-customer-name"
  api_base_url = "api-base-url"  # Optional
}
```

## Documentation

For detailed documentation on all available resources and data sources, visit the [Terraform Registry](https://registry.terraform.io/providers/step-security/stepsecurity/latest/docs).

## Examples

The `examples` directory contains sample configurations for various use cases:

- [Basic Provider Setup](examples/provider/)
- [User Management](examples/user/)
- [GitHub Repository Settings](examples/github-notification-settings/)
- [Policy-Driven PRs](examples/policy-driven-pr/)

## Development

### Building the Provider

1. Clone the repository:
```bash
git clone https://github.com/step-security/terraform-provider-stepsecurity.git
cd terraform-provider-stepsecurity
```

2. Build the provider:
```bash
go build -o terraform-provider-stepsecurity
```


### Running Tests

```bash
# Run unit tests
go test ./...

# Run acceptance tests (requires API credentials)
TF_ACC=1 go test ./... -v
```

### Testing Locally

After building the provider, you can test it locally by creating a `.terraformrc` file in your home directory:

```hcl
provider_installation {
  dev_overrides {
    "step-security/stepsecurity" = "/path/to/terraform-provider-stepsecurity"
  }
  direct {}
}
```

### Reporting Issues

If you encounter any issues or have feature requests, please [create an issue](https://github.com/step-security/terraform-provider-stepsecurity/issues/new) on GitHub.

## Support

- [Documentation](https://registry.terraform.io/providers/step-security/stepsecurity/latest/docs)
- [GitHub Issues](https://github.com/step-security/terraform-provider-stepsecurity/issues)
- [StepSecurity Support](https://www.stepsecurity.io/support)
