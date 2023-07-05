using System.Collections;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.OpenSsl;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Utilities;

namespace MyHttpProxy;

public abstract class CertificateGeneration
{
    private static string PRIVATE_KEY_STRING = CAInjector.RetrievePrivateKey();
    
    /// <summary>
    /// Creates a tuple of a private key and a self-signed certificate.
    /// </summary>
    /// <returns></returns>
    public static (
        string privateKey, 
        string certificateText) GenerateCaKeyPair()
    {
        // Generate a private key
        var generator = new RsaKeyPairGenerator();
        generator.Init(new KeyGenerationParameters(new SecureRandom(), 2048));
        var keyPair = generator.GenerateKeyPair();

        // Export the private key
        TextWriter privateKeyWriter = new StringWriter();
        var pemPrivateKeyWriter = new PemWriter(privateKeyWriter);
        pemPrivateKeyWriter.WriteObject(keyPair.Private);
        pemPrivateKeyWriter.Writer.Flush();
        var privateKey = privateKeyWriter.ToString();

        // Generate a self-signed certificate
        var certificateGenerator = new X509V3CertificateGenerator();
        certificateGenerator.SetSerialNumber(BigInteger.ValueOf(1));
        certificateGenerator.SetIssuerDN(new X509Name($"CN={CA_COMMON_NAME}"));
        certificateGenerator.SetSubjectDN(new X509Name($"CN={CA_COMMON_NAME}"));
        certificateGenerator.SetNotBefore(DateTime.UtcNow.Date);
        certificateGenerator.SetNotAfter(DateTime.UtcNow.Date.AddYears(1));
        certificateGenerator.SetPublicKey(keyPair.Public);
        certificateGenerator.SetSignatureAlgorithm("SHA256WithRSA");

        var certificate = certificateGenerator.Generate(keyPair.Private);

        // Export the self-signed certificate
        var certificateWriter = new StringWriter();
        var pemCertificateWriter = new PemWriter(certificateWriter);
        pemCertificateWriter.WriteObject(certificate);
        pemCertificateWriter.Writer.Flush();
        var certificateText = certificateWriter.ToString();
        
        return (privateKey, certificateText)!;
    }
    
    /// <summary>
    /// Generates a valid trusted certificate based on a given domain name.
    /// </summary>
    /// <param name="subjectName"></param>
    public static X509Certificate2 GenerateCertificate(string subjectName)
    {
        var random = new SecureRandom();
        var certificateGenerator = new X509V3CertificateGenerator();

        // set random serial number
        var serialNumber = BigIntegers.CreateRandomInRange(
            BigInteger.One, 
            BigInteger.ValueOf(long.MaxValue), random);
        certificateGenerator.SetSerialNumber(serialNumber);
        
        // generate and set subject
        {
            var attributes = new Dictionary<DerObjectIdentifier, string>
            {
                { X509Name.CN, $"*.{subjectName}" },
                { X509Name.OU, CA_COMMON_NAME },
                { X509Name.O, CA_COMMON_NAME },
            };
            certificateGenerator.SetSubjectDN(new EasyX509Name(attributes));
        }
        
        // generate and set issuer
        {
            var attributes = new Dictionary<DerObjectIdentifier, string>
            {
                { X509Name.O, CA_COMMON_NAME },
                { X509Name.OU, "Local Certificate Authority" },
                { X509Name.CN, CA_COMMON_NAME },
            };
            certificateGenerator.SetIssuerDN(new EasyX509Name(attributes));
        }

        // add the `subjectAltName` extension and spoof the values
        // to equal the http proxy server's IP.
        SpoofSubjectAlternativeNames(ref certificateGenerator, subjectName);
        
        // set the date/timespan of the certificate
        certificateGenerator.SetNotBefore(DateTime.UtcNow.Date);
        certificateGenerator.SetNotAfter(DateTime.UtcNow.Date.AddYears(1));

        // get the private key from PRIVATE_KEY_STRING
        var privateKeyReader = new PemReader(
            new StringReader(PRIVATE_KEY_STRING));
        var privateKey = ((AsymmetricCipherKeyPair)
            privateKeyReader.ReadObject()).Private;
        
        // generate a public key based on the private key
        var keyPairGenerator = new RsaKeyPairGenerator();
        keyPairGenerator.Init(new RsaKeyGenerationParameters(
            ((RsaPrivateCrtKeyParameters)privateKey).PublicExponent,
            random, 2048, 100));
        var subjectKeyPair = keyPairGenerator.GenerateKeyPair();
        certificateGenerator.SetPublicKey(subjectKeyPair.Public);
        
        // sign the certificate and generate it
        var signatureFactory = new Asn1SignatureFactory(
            "SHA256WithRSA", privateKey, random);
        var certificate = certificateGenerator.Generate(signatureFactory);
        
        // todo: remove
        
        // store file so I can use openssl to verify
        var certificateWriter = new StringWriter();
        var pemCertificateWriter = new PemWriter(certificateWriter);
        pemCertificateWriter.WriteObject(certificate);
        pemCertificateWriter.Writer.Flush();
        var certificateText = certificateWriter.ToString();
        File.WriteAllText(
            Path.Join(
                Directory.GetCurrentDirectory(),
                "test.crt"), 
            certificateText);
        
        // todo: remove
        
        var certData = certificate.GetEncoded();
        var rsa = ConvertToRsa(subjectKeyPair);
        var dotNetCertificate = new X509Certificate2(certData)
            .CopyWithPrivateKey(rsa);

        // @see: https://github.com/dotnet/runtime/issues/45680
        if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        {
            return new X509Certificate2(
                dotNetCertificate.Export(
                   X509ContentType.Pkcs12));
        }
        
        return dotNetCertificate;
    }

    private const string CA_COMMON_NAME = "DummyCommonName";
    
    /// <summary>
    /// Converts AsymmetricCipherKeyPair to RSA.
    /// </summary>
    /// <param name="keyPair"></param>
    private static RSA ConvertToRsa(AsymmetricCipherKeyPair keyPair)
    {
        var privateKeyParams = (RsaPrivateCrtKeyParameters)keyPair.Private;

        var rsaParameters = new RSAParameters
        {
            Modulus = privateKeyParams.Modulus.ToByteArrayUnsigned(),
            Exponent = privateKeyParams.PublicExponent.ToByteArrayUnsigned(),
            P = privateKeyParams.P.ToByteArrayUnsigned(),
            Q = privateKeyParams.Q.ToByteArrayUnsigned(),
            DP = privateKeyParams.DP.ToByteArrayUnsigned(),
            DQ = privateKeyParams.DQ.ToByteArrayUnsigned(),
            InverseQ = privateKeyParams.QInv.ToByteArrayUnsigned(),
            D = privateKeyParams.Exponent.ToByteArrayUnsigned()
        };

        var rsa = RSA.Create();
        rsa.ImportParameters(rsaParameters);

        return rsa;
    }
    
    /// <summary>
    /// Creates and spoofs the `subjectAltName` extension of a given
    /// certificate generator.
    /// </summary>
    /// <param name="certificateGenerator"></param>
    /// <param name="domain"></param>
    private static void SpoofSubjectAlternativeNames(
        ref X509V3CertificateGenerator certificateGenerator,
        string domain)
    {
        var dnsNames = new [] {
            domain,
            "www." + domain,
            "*." + domain
        };

        var ipNames = new [] {
            "127.0.0.1",
            "0.0.0.0"
        };
        
        var subjectAltNames = new GeneralName[dnsNames.Length + ipNames.Length];
        
        // populate array with DNS names and IP addresses
        for (var i = 0; i < dnsNames.Length; i++)
        {
            var dnsName = new DerIA5String(dnsNames[i]);
            var dnsGeneralName = new GeneralName(
                GeneralName.DnsName, dnsName);
            subjectAltNames[i] = dnsGeneralName;
        }
        for (var i = 0; i < ipNames.Length; i++)
        {
            var ipAddress = IPAddress.Parse(ipNames[i]).GetAddressBytes();
            var ipOctetString = new DerOctetString(ipAddress);
            var ipGeneralName = new GeneralName(
                GeneralName.IPAddress, ipOctetString);
            subjectAltNames[dnsNames.Length + i] = ipGeneralName;
        }
        
        var subjectAltNameExtension = new DerSequence(subjectAltNames);
        
        certificateGenerator.AddExtension(
            X509Extensions.SubjectAlternativeName, 
            false,
            subjectAltNameExtension);
    }

    /// <summary>
    /// Simpler way to quickly create an X509Name by only
    /// providing a dictionary. 
    /// </summary>
    private class EasyX509Name: X509Name
    {
        public EasyX509Name(Dictionary<DerObjectIdentifier, string> attributes)
            : base(GenerateOrdering(attributes), attributes) { }

        private static ArrayList GenerateOrdering(
            Dictionary<DerObjectIdentifier, string> attributes)
        {
            var ordering = new ArrayList();
            foreach (var pair in attributes)
            {
                ordering.Add(pair.Key);
            }
            return ordering;
        }
    }
}