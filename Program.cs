using System;
using System.IO;

using pdftron.Crypto;
using pdftron.PDF;

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
      const string outputPdfName = "hsmSigned.pdf";
      string outputPathAndName = $"{pdfDirectory}{outputPdfName}";
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
      /**
       * TODO @colim 2021-11-26
       * It would probably be cleaner to keep the instantiations of PDFDoc inside of the instances of the PDFNetWrapper class
       */
      PDFDoc doc = new PDFDoc(pathToPdf);
      PDFDoc docWithSigDictForCustomSigning = pdfnetWrapper.PreparePdfForCustomSigning(doc, signatureFieldName);
      byte[] pdfDigest = pdfnetWrapper.GetPdfDigest();
      AzureHSMService azureHSMService = new AzureHSMService();

      DigestAlgorithm.Type in_digest_algorithm_type = DigestAlgorithm.Type.e_sha256;
      pdftron.Crypto.X509Certificate signer_cert = pdfnetWrapper.CreatePdftronX509Certificate(azureHSMService.GetPublicCertificateInPemFormat());
      byte[] pades_versioned_ess_signing_cert_attribute = DigitalSignatureField.GenerateESSSigningCertPAdESAttribute(signer_cert, in_digest_algorithm_type);
      byte[] signedAttrs = DigitalSignatureField.GenerateCMSSignedAttributes(pdfDigest, pades_versioned_ess_signing_cert_attribute);
      byte[] signedAttrsDigest = DigestAlgorithm.CalculateDigest(in_digest_algorithm_type, signedAttrs);

      // Azure KeyVault signing
      byte[] rsaSignResult = azureHSMService.Sign(signedAttrsDigest);

      X509Certificate[] chain_certs = new X509Certificate[] { signer_cert };
      int[] digest_alg_oid_nums = new int[] { 2, 16, 840, 1, 101, 3, 4, 2, 1 }; // sha-256
      ObjectIdentifier digest_algorithm_oid = new ObjectIdentifier(digest_alg_oid_nums);
      // Use appropriate signature algorithm OID
      //int[] sig_alg_oid_nums = new int[]{ 1, 2, 840, 113549, 1, 1, 1 }; // rsaEncryption
      int[] sig_alg_oid_nums = new int[] { 1, 2, 840, 113549, 1, 1, 11 }; // sha256WithRSAEncryption
      ObjectIdentifier signature_algorithm_oid = new ObjectIdentifier(sig_alg_oid_nums);

      byte[] signature = DigitalSignatureField.GenerateCMSSignature(
        signer_cert,
        chain_certs,
        digest_algorithm_oid,
        signature_algorithm_oid,
        rsaSignResult,
        signedAttrs
      );
      DigitalSignatureField digitalSignatureField = pdfnetWrapper.GetDigitalSignatureField();
      docWithSigDictForCustomSigning.SaveCustomSignature(
        signature,
        digitalSignatureField,
        outputPathAndName
      );
    }
  }
}
