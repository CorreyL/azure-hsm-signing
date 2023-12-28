using System;
using System.Diagnostics;

using Azure;
using Azure.Identity;
using Azure.Security.KeyVault.Keys;
using Azure.Security.KeyVault.Certificates;
using Azure.Security.KeyVault.Keys.Cryptography;

namespace azure_hsm_signing {
  public class AzureHSMService
  {
    private readonly string debugCategory = "AzureHSMService";
    private CryptographyClient RsaCryptoClient { get; set; }
    private Response<KeyVaultCertificateWithPolicy> certResponse { get; set; }
    public AzureHSMService()
    {
      // The URL that the KeyVault is hosted at on Azure
      const string hsmUrl = "https://apryse.vault.azure.net/";
      // The name of the non-exportable Certificate under the KeyVault named pdftron-hsm-digsigs
      const string certificateName = "Pdftron";

      KeyClient keyClient = new KeyClient(new Uri(hsmUrl), new VisualStudioCredential());
      CertificateClient certificateClient = new CertificateClient(new Uri(hsmUrl), new VisualStudioCredential());
      certResponse = certificateClient.GetCertificate(certificateName);
      KeyVaultKey rsaKey = keyClient.GetKey(certificateName);
      Debug.WriteLine($"Key is returned with name {rsaKey.Name} and type {rsaKey.KeyType}", debugCategory);

      RsaCryptoClient = new CryptographyClient(rsaKey.Id, new DefaultAzureCredential());
    }

    public byte[] Sign(byte[] digest, SignatureAlgorithm? signatureAlgorithm = null)
    {
      // Since the default value in the function signature needs to be a compile-time constant, this is a workaround
      SignatureAlgorithm algorithm = signatureAlgorithm ?? SignatureAlgorithm.RS256;
      SignResult rsaSignResult = RsaCryptoClient.Sign(algorithm, digest);
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
      VerifyResult rsaVerifyResult = RsaCryptoClient.Verify(algorithm, originalDigest, signedDigest);
      Console.WriteLine($"Verified the signature using the algorithm {rsaVerifyResult.Algorithm}, with key:\n{rsaVerifyResult.KeyId}.\n\nSignature is valid:\n{rsaVerifyResult.IsValid}");
    }

    public byte[] GetPublicCertificateInPemFormat()
    {
      return certResponse.Value.Cer;
    }
  }
}
