## Azure HSM Signing

This repository is a sample for how to perform signing and verification of arbitrary data with [Azure KeyVault](https://azure.microsoft.com/en-us/services/key-vault/)

## Prerequisites

Before running this program, you must have the following environment variables declared:

```PowerShell
# https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/Overview
$Env:AZURE_TENANT_ID="your-azure-tenant-id"
# https://portal.azure.com/#blade/Microsoft_AAD_IAM/ActiveDirectoryMenuBlade/RegisteredApps
$Env:AZURE_CLIENT_ID="your-azure-client-id"
$Env:AZURE_CLIENT_SECRET="your-client-secret-associated-with-azure-client-id"
```
