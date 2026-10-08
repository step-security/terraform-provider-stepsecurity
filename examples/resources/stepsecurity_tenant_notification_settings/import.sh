#!/bin/bash

# There is exactly one tenant notification settings record, and the tenant comes
# from the provider configuration, so the import ID identifies nothing and is
# ignored. Pass the customer name as a placeholder.

terraform import stepsecurity_tenant_notification_settings.this abcdefg
