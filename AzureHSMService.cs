using System;
using System.Diagnostics;

using Azure.Identity;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Keys.Cryptography;

namespace azure_hsm_signing {
  public class AzureHSMService
  {
    private readonly string debugCategory = "AzureHSMService";
    CryptographyClient rsaCryptoClient;
    public AzureHSMService()
    {
      // The URL that the KeyVault is hosted at on Azure
      const string hsmUrl = "https://pdftron-hsm-digsigs.vault.azure.net/";
      // The name of the non-exportable Certificate under the KeyVault named pdftron-hsm-digsigs
      const string certificateName = "hsm-test";

      KeyClient keyClient = new KeyClient(new Uri(hsmUrl), new VisualStudioCredential());
      KeyVaultKey rsaKey = keyClient.GetKey(certificateName);
      Debug.WriteLine($"Key is returned with name {rsaKey.Name} and type {rsaKey.KeyType}", debugCategory);

      rsaCryptoClient = new CryptographyClient(rsaKey.Id, new DefaultAzureCredential());
    }

    public byte[] Sign(byte[] digest, SignatureAlgorithm? signatureAlgorithm = null)
    {
      // Since the default value in the function signature needs to be a compile-time constant, this is a workaround
      SignatureAlgorithm algorithm = signatureAlgorithm ?? SignatureAlgorithm.RS256;
      SignResult rsaSignResult = rsaCryptoClient.Sign(algorithm, digest);
      Debug.WriteLine(
        $"Signed digest using the algorithm {rsaSignResult.Algorithm}, with key {rsaSignResult.KeyId}. The resulting signature is {Convert.ToBase64String(rsaSignResult.Signature)}",
        debugCategory
      );
      return rsaSignResult.Signature;
    }

    public void Verify(byte[] originalDigest, byte[] signedDigest, SignatureAlgorithm? signatureAlgorithm = null)
    {
      // Since the default value in the function signature needs to be a compile-time constant, this is a workaround
      SignatureAlgorithm algorithm = signatureAlgorithm ?? SignatureAlgorithm.RS256;
      VerifyResult rsaVerifyResult = rsaCryptoClient.Verify(algorithm, originalDigest, signedDigest);
      Console.WriteLine($"Verified the signature using the algorithm {rsaVerifyResult.Algorithm}, with key:\n{rsaVerifyResult.KeyId}.\n\nSignature is valid:\n{rsaVerifyResult.IsValid}");
    }
  }
}
