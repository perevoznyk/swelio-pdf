//===============================================================================
// Copyright (c) Serhiy Perevoznyk.  All rights reserved.
// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY
// OF ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT
// LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
// FITNESS FOR A PARTICULAR PURPOSE.
//===============================================================================

using Swelio.Engine;
using System;
using System.Collections.Generic;
using iTextSharp.text.pdf.security;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Digests;
using Org.BouncyCastle.Pkix;
using Org.BouncyCastle.X509.Store;
using System.Security.Cryptography;
using System.IO;

namespace Swelio.Pdf
{
    public class EidSignature : IExternalSignature, IDisposable
    {
        private Swelio.Engine.Manager engine = new Manager();
        private int readerIndex = -1;
        private bool disposedValue = false;
        private string pin;
        private string serialNumber;
        private string cacheFolder;


        public string GetEncryptionAlgorithm()
        {
            return "RSA";
        }

        public string GetHashAlgorithm()
        {
            return "SHA256";
        }

        public int ReadersCount
        {
            get { return engine.ReaderCount; }
        }
        /// <summary>
        /// Checks whether certificate is self-signed
        /// </summary>
        /// <param name="certificate">Certificate to be checked</param>
        /// <returns>True if certificate is self-signed; false otherwise</returns>
        public static bool IsSelfSigned(Org.BouncyCastle.X509.X509Certificate certificate)
        {
            if (certificate == null)
                throw new ArgumentNullException("certificate");

            try
            {
                certificate.Verify(certificate.GetPublicKey());
                return true;
            }
            catch (Org.BouncyCastle.Security.InvalidKeyException)
            {
                return false;
            }
        }

        /// <summary>
        /// Converts raw certificate data to the instance of BouncyCastle X509Certificate class
        /// </summary>
        /// <param name="data">Raw certificate data</param>
        /// <returns>Instance of BouncyCastle X509Certificate class</returns>
        public static Org.BouncyCastle.X509.X509Certificate ToBouncyCastleObject(byte[] data)
        {
            if (data == null)
                throw new ArgumentNullException("data");

            Org.BouncyCastle.X509.X509CertificateParser _x509CertificateParser = new Org.BouncyCastle.X509.X509CertificateParser();
            Org.BouncyCastle.X509.X509Certificate bcCert = _x509CertificateParser.ReadCertificate(data);
            if (bcCert == null)
                throw new CryptographicException("Cannot find the requested object.");

            return bcCert;
        }


        /// <summary>
        /// Builds certification path for provided signing certificate
        /// </summary>
        /// <param name="signingCertificate">Signing certificate</param>
        /// <param name="otherCertificates">Other certificates that should be used in path building process. Self-signed certificates from this list are used as trust anchors.</param>
        /// <returns>Certification path for provided signing certificate</returns>
        public ICollection<Org.BouncyCastle.X509.X509Certificate> BuildCertPath(byte[] signingCertificate, List<byte[]> otherCertificates)
        {
            if (signingCertificate == null)
                throw new ArgumentNullException("signingCertificate");

            List<Org.BouncyCastle.X509.X509Certificate> result = new List<Org.BouncyCastle.X509.X509Certificate>();

            Org.BouncyCastle.X509.X509Certificate signingCert = ToBouncyCastleObject(signingCertificate);



            Org.BouncyCastle.Utilities.Collections.ISet trustAnchors = new Org.BouncyCastle.Utilities.Collections.HashSet();
            List<Org.BouncyCastle.X509.X509Certificate> otherCerts = new List<Org.BouncyCastle.X509.X509Certificate>();

            if (IsSelfSigned(signingCert))
            {
                result.Add(signingCert);
            }
            else
            {
                otherCerts.Add(signingCert);

                if (otherCertificates != null)
                {
                    foreach (byte[] otherCertificate in otherCertificates)
                    {
                        Org.BouncyCastle.X509.X509Certificate otherCert = ToBouncyCastleObject(otherCertificate);
                        otherCerts.Add(ToBouncyCastleObject(otherCertificate));
                        if (IsSelfSigned(otherCert))
                            trustAnchors.Add(new TrustAnchor(otherCert, null));
                    }
                }

                if (trustAnchors.Count < 1)
                    throw new PkixCertPathBuilderException("Provided certificates do not contain self-signed root certificate");

                X509CertStoreSelector targetConstraints = new X509CertStoreSelector();
                targetConstraints.Certificate = signingCert;

                PkixBuilderParameters certPathBuilderParameters = new PkixBuilderParameters(trustAnchors, targetConstraints);
                certPathBuilderParameters.AddStore(X509StoreFactory.Create("Certificate/Collection", new X509CollectionStoreParameters(otherCerts)));
                certPathBuilderParameters.IsRevocationEnabled = false;

                PkixCertPathBuilder certPathBuilder = new PkixCertPathBuilder();
                PkixCertPathBuilderResult certPathBuilderResult = certPathBuilder.Build(certPathBuilderParameters);

                foreach (Org.BouncyCastle.X509.X509Certificate certPathCert in certPathBuilderResult.CertPath.Certificates)
                    result.Add(certPathCert);

                result.Add(certPathBuilderResult.TrustAnchor.TrustedCert);
            }

            return result;
        }

        public byte[] Sign(byte[] message)
        {
            int cnt = engine.ReaderCount;
            if (cnt == 0)
            {
                return null;
            }

            byte[] digest = null;
            digest = ComputeDigest(new Sha256Digest(), message);

            for (int i = 0; i < cnt; i++)
            {
                using (CardReader reader = engine.GetReader(i))
                {
                    if (reader != null)
                    {
                        using (Card card = reader.GetCard(true))
                        {
                            if (card != null)
                            {
                                if (card.EidCard)
                                {
                                    return Encryption.GenerateNonRepudiationSignature(reader, this.pin, digest, digest.Length);
                                }
                            }
                        }
                    }
                }
            }

            return null;
        }

        public List<byte[]> GetAllCertificates()
        {
            List<byte[]> certificates = new List<byte[]>();

            bool canRead = (readerIndex > -1);
            if (!canRead)
                canRead = IsCardInserted;

            if (canRead)
            {
                CreateCacheFolder();

                string fileName = Path.Combine(cacheFolder, serialNumber + ".ca");
                if (FileOperations.FileExists(fileName))
                {
                    certificates.Add(File.ReadAllBytes(fileName));
                }
                else
                {
                    CardReader reader = engine.GetReader(readerIndex);
                    if (reader != null)
                    {

                        Card card = reader.GetCard(true);

                        if (card != null)
                        {

                            byte[] result = card.ReadCertificate(CertificateType.CaCertificate);
                            if (result != null)
                            {
                                File.WriteAllBytes(fileName, result);
                                certificates.Add(result);
                            }
                        }
                    }
                }


                fileName = Path.Combine(cacheFolder, serialNumber + ".root");
                if (FileOperations.FileExists(fileName))
                {
                    certificates.Add(File.ReadAllBytes(fileName));
                }
                else
                {
                    CardReader reader = engine.GetReader(readerIndex);
                    if (reader != null)
                    {

                        Card card = reader.GetCard(true);

                        if (card != null)
                        {

                            byte[] result = card.ReadCertificate(CertificateType.RootCaCertificate);
                            if (result != null)
                            {
                                File.WriteAllBytes(fileName, result);
                                certificates.Add(result);
                            }
                        }
                    }
                }
            }

            return certificates;

        }

        public bool IsCardInserted
        {
            get
            {
                int cnt = engine.ReaderCount;
                if (cnt == 0)
                {
                    this.readerIndex = -1;
                    this.serialNumber = null;
                    return false;
                }

                for (int i = 0; i < cnt; i++)
                {
                    using (CardReader reader = engine.GetReader(i))
                    {
                        if (reader != null)
                        {
                            using (Card card = reader.GetCard(true))
                            {
                                if (card != null)
                                {
                                    if (card.EidCard)
                                    {
                                        this.readerIndex = reader.Index;
                                        this.serialNumber = card.SerialNumber;
                                        return true;
                                    }
                                }
                            }
                        }
                    }
                }

                this.readerIndex = -1;
                this.serialNumber = null;
                return false;

            }
        }

        internal void CreateCacheFolder()
        {
            if (!FileOperations.DirectoryExists(cacheFolder))
            {
                Directory.CreateDirectory(cacheFolder);
            }
        }

        public byte[] GetSigningCertificate()
        {
            bool canRead = (readerIndex > -1);
            if (!canRead)
                canRead = IsCardInserted;

            if (canRead)
            {
                CreateCacheFolder();
                string fileName = Path.Combine(cacheFolder, serialNumber + ".crt");
                if (FileOperations.FileExists(fileName))
                {
                    return File.ReadAllBytes(fileName);
                }
                else
                {
                    CardReader reader = engine.GetReader(readerIndex);
                    if (reader == null)
                        return null;

                    Card card = reader.GetCard(true);

                    if (card == null)
                        return null;

                    byte[] result = card.ReadCertificate(CertificateType.NonRepudiationCertificate);
                    if (result != null)
                    {
                        File.WriteAllBytes(fileName, result);
                    }
                    return result;
                }
            }
            else
            {
                return null;
            }
        }

        /// <summary>
        /// Computes hash of the data
        /// </summary>
        /// <param name="digest">Hash algorithm implementation</param>
        /// <param name="data">Data that should be processed</param>
        /// <returns>Hash of data</returns>
        private byte[] ComputeDigest(IDigest digest, byte[] data)
        {
            if (digest == null)
                throw new ArgumentNullException("digest");

            if (data == null)
                throw new ArgumentNullException("data");

            byte[] hash = new byte[digest.GetDigestSize()];

            digest.Reset();
            digest.BlockUpdate(data, 0, data.Length);
            digest.DoFinal(hash, 0);

            return hash;
        }


        #region IDisposable Support

        public EidSignature(string pin)
        {
            this.pin = pin;
            this.cacheFolder = Path.Combine(FileOperations.IncludeTrailingPathDelimiter(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData)), "cache.eid");
            engine.Active = true;
        }

        protected virtual void Dispose(bool disposing)
        {
            if (!disposedValue)
            {
                if (disposing)
                {
                    engine.Active = false;
                }

                engine.Dispose();
                disposedValue = true;
            }
        }

        ~EidSignature()
        {
            Dispose(false);
        }

        // This code added to correctly implement the disposable pattern.
        public void Dispose()
        {
            Dispose(true);
            GC.SuppressFinalize(this);
        }
        #endregion
    }
}
