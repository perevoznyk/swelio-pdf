using iTextSharp.text.pdf;
using iTextSharp.text.pdf.security;
using System;
using System.Collections.Generic;
using System.IO;
using Utility.CommandLine;
using Swelio.Pdf;

namespace PDFSigner
{
    enum ExitCode : int
    {
        Success = 0,
        NoInputFile = 1,
        NoOutputFile = 2,
        NoPin = 3,
        NoReader = 4,
        SignFailed = 5,
        NoCertificate = 6,
        NoCardReader = 7,
        NoCardInserted = 8,
        UnknownError = 32
    }

    class Program
    {
        [Argument('i', "in")]
        static string SourceFile { get; set; }

        [Argument('o', "out")]
        static string DestinationFile { get; set; }

        [Argument('p', "pin")]
        static string Pincode { get; set; }

        static void PrintUsage()
        {
            Console.WriteLine("usage: PDFSigner -i input file -o output file -p pincode");
        }

        public static void AddLtv(String src, String dest, IOcspClient ocsp, ICrlClient crl, ITSAClient tsa)
        {
            PdfReader r = new PdfReader(src);
            FileStream fos = new FileStream(dest, FileMode.Create);
            PdfStamper stp = PdfStamper.CreateSignature(r, fos, '\0', null, true);
            Dictionary<String, String> info = r.Info;
            stp.MoreInfo = info;
            LtvVerification v = stp.LtvVerification;
            AcroFields fields = stp.AcroFields;
            List<String> names = fields.GetSignatureNames();
            String sigName = names[names.Count - 1];
            PdfPKCS7 pkcs7 = fields.VerifySignature(sigName);
            if (pkcs7.IsTsp)
                v.AddVerification(sigName, ocsp, crl, LtvVerification.CertificateOption.SIGNING_CERTIFICATE, LtvVerification.Level.OCSP_CRL, LtvVerification.CertificateInclusion.NO);
            else foreach (String name in names)
                    v.AddVerification(name, ocsp, crl, LtvVerification.CertificateOption.WHOLE_CHAIN, LtvVerification.Level.OCSP_OPTIONAL_CRL, LtvVerification.CertificateInclusion.NO);
            PdfSignatureAppearance sap = stp.SignatureAppearance;
            LtvTimestamp.Timestamp(sap, tsa, null);
        }


        static int Main(string[] args)
        {
            if (args.Length == 0)
            {
                PrintUsage();
                return (int)ExitCode.Success;
            }

            Arguments.Populate();

            if (string.IsNullOrEmpty(SourceFile))
            {
                PrintUsage();
                return (int)ExitCode.NoInputFile;
            }

            if (string.IsNullOrEmpty(DestinationFile))
            {
                PrintUsage();
                return (int)ExitCode.NoOutputFile;
            }

            if (string.IsNullOrEmpty(Pincode))
            {
                PrintUsage();
                return (int)ExitCode.NoPin;
            }

            using (EidSignature eidSignature = new EidSignature(Pincode))
            {
                if (eidSignature.ReadersCount == 0)
                {
                    Console.WriteLine("No card reader connected");
                    return (int)ExitCode.NoCardReader;
                }

                if (eidSignature.IsCardInserted == false)
                {
                    Console.WriteLine("No eid card inserted in the reader");
                    return (int)ExitCode.NoCardInserted;
                }

                // When signing certificate is stored on the token it can be usually read with GetSigningCertificate() method
                byte[] signingCertificate = eidSignature.GetSigningCertificate();
                if (signingCertificate == null)
                {
                    Console.WriteLine("No signing certificate found");
                    return (int)ExitCode.NoCertificate;
                }


                // All certificates stored on the token can be usually read with GetAllCertificates() method
                List<byte[]> otherCertificates = eidSignature.GetAllCertificates();

                // Build certification path for the signing certificate
                ICollection<Org.BouncyCastle.X509.X509Certificate> certPath = eidSignature.BuildCertPath(signingCertificate, otherCertificates);

                TSAClientBouncyCastle tsaClient = new TSAClientBouncyCastle("http://tsa.belgium.be/connect");
            
                // Read unsigned PDF document
                using (PdfReader pdfReader = new PdfReader(SourceFile))
                {

                    string tmpSigned = Path.GetTempFileName();

                    // Create output stream for signed PDF document
                    using (FileStream outputStream = new FileStream(tmpSigned, FileMode.Create))
                    {
                        // Create PdfStamper that applies extra content to the PDF document
                        using (PdfStamper pdfStamper = PdfStamper.CreateSignature(pdfReader, outputStream, '\0'))
                        {
                            PdfSignatureAppearance appearance = pdfStamper.SignatureAppearance;

                            List<ICrlClient> crlList = new List<ICrlClient>();
                            crlList.Add(new CrlClientOnline("http://crl.eid.belgium.be/belgium2.crl"));
                            crlList.Add(new CrlClientOnline("http://crl.eid.belgium.be/belgium3.crl"));
                            crlList.Add(new CrlClientOnline("http://crl.eid.belgium.be/belgium4.crl"));

                            // Sign PDF document
                            try
                            {
                                MakeSignature.SignDetached(appearance, eidSignature, certPath, crlList, null, tsaClient, 0, CryptoStandard.CADES);
                            }
                            catch (NullReferenceException e)
                            {
                                Console.WriteLine("Can't read the certificate from the card");
                                return (int)ExitCode.NoCertificate;
                            }
                            catch (Exception e)
                            {
                                Console.WriteLine(e.Message);
                                return (int)ExitCode.UnknownError;
                            }
                        }
                    }

                    try
                    {
                        AddLtv(tmpSigned, DestinationFile, null, new CrlClientOnline(), tsaClient);
                    }
                    catch (Exception e)
                    {
                        Console.WriteLine(e.Message);
                        return (int)ExitCode.UnknownError;
                    }
                }
            }

            return (int)ExitCode.Success;
        }
    }
}
