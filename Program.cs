using System;
using System.IO;

using pdftron.PDF;

using System.Security.Cryptography;

namespace azure_hsm_signing
{
  class Program
  {
    static void Main(string[] args)
    {
      const string pdfDirectory = "../../../pdf/";
      const string nameOfFile = "waiver.pdf";
      const string signatureFieldName = "Signature1";
      const string pathToLicenseKey = "../../../.pdfnetlicensekey";
      if (!File.Exists(pathToLicenseKey))
      {
        throw new FileNotFoundException(pathToLicenseKey);
      };
      string pdfnetLicenseKey = File.ReadAllText(pathToLicenseKey).Trim();

      string pathToPdf = $"{pdfDirectory}{nameOfFile}";
      if (!File.Exists(pathToPdf))
      {
        throw new FileNotFoundException(pathToPdf);
      };

      PDFNetWrapper pdfnetWrapper = new PDFNetWrapper(pdfnetLicenseKey);
      PDFDoc doc = new PDFDoc(pathToPdf);
      PDFDoc docWithSigDictForCustomSigning = pdfnetWrapper.PreparePdfForCustomSigning(doc, signatureFieldName);
      byte[] pdfDigest = pdfnetWrapper.GetPdfDigest(docWithSigDictForCustomSigning, signatureFieldName);
      AzureHSMService azureHSMService = new AzureHSMService();
      // byte[] messageToSign = System.Text.Encoding.ASCII.GetBytes("Hello World");
      // byte[] hashValue = SHA256.Create().ComputeHash(messageToSign);
      byte[] signedDigest = azureHSMService.Sign(pdfDigest);
      azureHSMService.Verify(pdfDigest, signedDigest);
      /**
       * TODO @colim 2021-11-26
       * Add logic to build a PKCS#7 compliant message when the API is available in PDFNet
       */
      // byte[] pkcs7message;
      // pdfnetWrapper.SavePdfWithDigitalSignature(docWithSigDictForCustomSigning, signatureFieldName, pkcs7message, pdfDirectory, signatureFieldName);
    }
  }
}
