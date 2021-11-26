using pdftron;

namespace azure_hsm_signing
{
  public class PDFNetWrapper {
    public PDFNetWrapper(string licenseKey) {
      PDFNet.Initialize(licenseKey);
    }
  }
}
