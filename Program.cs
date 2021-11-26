using System;
using System.Security.Cryptography;

namespace azure_hsm_signing
{
  class Program
  {
    static void Main(string[] args)
    {
      AzureHSMService azureHSMService = new AzureHSMService();
      byte[] messageToSign = System.Text.Encoding.ASCII.GetBytes("Hello World");
      byte[] hashValue = SHA256.Create().ComputeHash(messageToSign);
      azureHSMService.Sign(hashValue);
    }
  }
}
