using System;

using pdftron;
using pdftron.Crypto;
using pdftron.PDF;
using pdftron.PDF.Annots;
using pdftron.SDF;

namespace azure_hsm_signing
{
  public class PDFNetWrapper {
    public PDFNetWrapper(string licenseKey) {
      Console.WriteLine($"PDFNet Version: {PDFNet.GetVersionString()}");
      PDFNet.Initialize(licenseKey);
    }
    public PDFDoc PreparePdfForCustomSigning(PDFDoc doc, string signatureFieldName, uint sizeOfContents = 7500)
    {
      Page page1 = doc.GetPage(1);
      Field found_approval_field = doc.GetField(signatureFieldName);
      bool isLockedByDigitalSignature = found_approval_field != null && found_approval_field.IsLockedByDigitalSignature();
      if (isLockedByDigitalSignature)
      {
        throw new Exception($"The field {signatureFieldName} is locked by a Digital Signature, and thus cannot be Digitally Signed again");
      }

      DigitalSignatureField certification_sig_field = doc.CreateDigitalSignatureField(signatureFieldName);
      SignatureWidget widgetAnnot = SignatureWidget.Create(doc, new Rect(), certification_sig_field);

      page1.AnnotPushBack(widgetAnnot);
      certification_sig_field.SetDocumentPermissions(DigitalSignatureField.DocumentPermissions.e_no_changes_allowed);

      // Prepare the signature and signature handler for signing.
      certification_sig_field.CreateSigDictForCustomSigning(
          "Adobe.PPKLite",
          // This chosen enum assumes you wish to use a PADES compliant signing mode
          // Please see this documentation for all possible options
          // https://www.pdftron.com/api/PDFTronSDK/dotnet/pdftron.PDF.DigitalSignatureField.SubFilterType.html
          DigitalSignatureField.SubFilterType.e_ETSI_CAdES_detached,
          sizeOfContents
      );

      byte[] newDoc = doc.Save(SDFDoc.SaveOptions.e_incremental);
      return new PDFDoc(newDoc, newDoc.Length);
    }

    public byte[] GetPdfDigest(PDFDoc doc, string signatureFieldName, DigestAlgorithm.Type digestAlgorithm = DigestAlgorithm.Type.e_sha256)
    {
      DigitalSignatureField certification_sig_field = doc.CreateDigitalSignatureField(signatureFieldName);
      return certification_sig_field.CalculateDigest(digestAlgorithm);
    }

    public void SavePdfWithDigitalSignature(PDFDoc doc, string signatureFieldName, byte[] pkcs7message, string pdfDirectory, string nameOfFile)
    {
      DigitalSignatureField certification_sig_field = doc.CreateDigitalSignatureField(signatureFieldName);
      doc.SaveCustomSignature(
        pkcs7message,
        certification_sig_field,
        $"{pdfDirectory}{nameOfFile}"
      );
    }
    public pdftron.Crypto.X509Certificate CreatePdftronX509Certificate(byte[] certificateInPemFormat)
    {
      X509Certificate[] chain_certs = new X509Certificate[] { new X509Certificate(certificateInPemFormat) };
      return new pdftron.Crypto.X509Certificate(certificateInPemFormat);
    }
  }
}
