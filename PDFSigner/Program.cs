using System;
using System.Collections.Generic;
using System.IO;
using Utility.CommandLine;
using Swelio.Pdf;
using iText.Signatures;
using iText.Kernel.Pdf;
using Org.BouncyCastle.X509;

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
                Org.BouncyCastle.X509.X509Certificate bcCert = new X509CertificateParser().ReadCertificate(signingCertificate);
                Org.BouncyCastle.X509.X509Certificate[] chain = new Org.BouncyCastle.X509.X509Certificate[1] { bcCert };
                //ICipherParameters pk = signatureCert.GetECDsaPrivateKey();

                TSAClientBouncyCastle tsaClient = new TSAClientBouncyCastle("http://tsa.belgium.be/connect");
            
                // Read unsigned PDF document
                using (PdfReader pdfReader = new PdfReader(SourceFile))
                {
                    using (FileStream outputStream = new FileStream(DestinationFile, FileMode.Create))
                    {
                        // Create PdfStamper that applies extra content to the PDF document
                        
                        StampingProperties properties = new StampingProperties();
                        properties.UseAppendMode();
                        
                        PdfSigner signer = new PdfSigner(pdfReader, outputStream, properties);
                        {
                            PdfSignatureAppearance appearance = signer.GetSignatureAppearance();

                            List<ICrlClient> crlList = new List<ICrlClient>();
                            crlList.Add(new CrlClientOnline("http://crl.eid.belgium.be/belgium2.crl"));
                            crlList.Add(new CrlClientOnline("http://crl.eid.belgium.be/belgium3.crl"));
                            crlList.Add(new CrlClientOnline("http://crl.eid.belgium.be/belgium4.crl"));

                            // Sign PDF document
                            try
                            {
                                signer.SignDetached(eidSignature, chain, crlList, null, tsaClient, 0, PdfSigner.CryptoStandard.CADES);
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

        
                }
            }

            return (int)ExitCode.Success;
        }
    }
}
