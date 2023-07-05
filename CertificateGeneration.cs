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
    private const string CA_COMMON_NAME = "Hoody Local Network";
    
    private const string PRIVATE_KEY_STRING = "-----BEGIN RSA PRIVATE KEY-----\r\nMIIEpAIBAAKCAQEArIFIhY2ZKNy6jJL7BF9yxpknLTQvWwoLpF7PIWS2F4KbeExm\r\nwy9OLI13dbL9XyvlBoD3s+J/d/YYAjfgRjywzOAF3Ruo0/wF7NcAscNiT6gD8WMi\r\nY3W6ntQHdh1GN5+heHqc3G/BmE7L/n8K9L9Jrd/tCfZWr3YG/An37+Mhk4u2Tqll\r\nlJDoGRq5n+Y9u3RYeAYIj9GDcH4r6G9kWVPJR4dRuPRRODRWb5efGpOg1ac4B3qa\r\n6z4yFdI/+fRYFznfvh/tAD35VSVumNgO+aDoUuipR56e3HZ9o9rNUHsbZ8AtkpXs\r\nMyeoy+DFJ8anc8OH8fk+K9CujPaVLChmNKyIrQIDAQABAoIBACgd9MiiUnEPTA7v\r\nC5NLwzxuV48KqMyqPGTga5kfe71h8Vf7pJZVxP9VcuebVZMxeRSXH4Pk87HpOFIj\r\nvnN3H8K1goeWLCAIZzRaF94/SvitYSVc4Z1xvpG7S3Trf+3loL6M/TfCgaozAPvR\r\nfbHHXpIiFlUPxb8OWrd4dgGCt8dA/usrCxEJrrVLiLsUOAQ8vOEWw1uAth/akEES\r\nwfb7yiVdNz0v4br9vKmhQUOMy6Jn8F27mhnC4IS2SquQjEnlKYSgCNH4EHDlgqhd\r\nGg+Jr7b2IYY4xe/VILGUz+sFcd5zYSkwIKjInzSR4LHxYeffV5YmlL26MihAGXfa\r\nbHsR9aECgYEA8Bf98dfKvKH9KxZJzKQNyx1yDP3NmFoYlAhE/kC4IfyHrd8qZrEZ\r\n79ZvZrNpCEPhR0KY9CZghQWTP/Dw4N9GgH3qaUbcihcUJVUXB89UexFOLg6qoidn\r\nexdLlrmkqgmJQA7Y5jC/q+NYY3P2WRxvv/whpRSX7rqyzxELre2OuSUCgYEAt+77\r\nTNWr0eNqybxnzIrVErkqtaynZBlTIbuqfZUX3RcspTRa5ANB2HDYn0DI4sqFG9Mk\r\neM6O3Fp1ITpkeDxYB0GG1lBedGIHwMr0mpR5sJ4J782ZiKGXDiB/Q8K9B/hJlCmz\r\n43oHPRGiE4h6Bf43UdH2Hp69QtzKwfU4bc8uDukCgYBV4C77nrSsLcCQ9cLlyFQK\r\nr3iIvwsXkDo0UJTk4B88QMgC38yZuITPbUKhWFCcHTNpup9czJE/YxQdDcAKnrHn\r\n6aG7kBX36nNROxMmvvi3oCP3g1Vy9Gcl9toZikMkco6989GO3Cbig0mtIOAfVXV/\r\nFN6v3iLNx8eHGtCzoEGpZQKBgQCrzP7RL6tDaqXuNJrHhM2spWPtOY1IhBcQJRgE\r\nIOSfT+wViydyXlB8eDr91SdOHlfiO3+Pj3AFBkDtfnsli0e1z1DAkWUIVCBlxaxf\r\nTluzyooBgQrtgfFz8oqsohKqhRFE4QbzbKGiOvwmPo2rV14YgILg6uhgsZZ5QDEq\r\n8B9XMQKBgQDNhH8UZrzrm/k5gxdyXMsG7J1mJEMFq9FPDVeuCAnQqulazZ80om2E\r\nQaZm0jG3WOHT5nf1NfC98R4bDEYHCkSnkm7M4HGt+LBGT572XlD9TtfDtSkd55OE\r\nOZo0wdSzZDzIOnqDMQ9Wm+mxoR/l2iTQ5+fPgn+HS9lxmlq86iC85Q==\r\n-----END RSA PRIVATE KEY-----";
    
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
                { X509Name.L, "Antartica" },
                { X509Name.ST, "Antartica" },
                { X509Name.C, "AQ" }
            };
            certificateGenerator.SetSubjectDN(new EasyX509Name(attributes));
        }
        
        // generate and set issuer
        {
            var attributes = new Dictionary<DerObjectIdentifier, string>
            {
                { X509Name.ST, "Antartica" },
                { X509Name.L, "Antartica" },
                { X509Name.O, CA_COMMON_NAME },
                { X509Name.OU, "Local Certificate Authority" },
                { X509Name.C, "AQ" },
                { X509Name.E, "ca@hoody.local" },
                { X509Name.CN, CA_COMMON_NAME },
                { new DerObjectIdentifier(
                    "1.2.840.113549.1.9.20"), "Hoody Local Security" }
                
            };
            certificateGenerator.SetIssuerDN(new EasyX509Name(attributes));
        }

        // add the `subjectAltName` extension and spoof the values
        // to equal the http proxy server's IP.
        SpoofSubjectAlternativeNames(ref certificateGenerator, subjectName);
        
        // set the date/timespan of the certificate
        certificateGenerator.SetNotBefore(DateTime.UtcNow.Date.Subtract(
            new TimeSpan(30, 0, 0)));
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
        
        //  sign the certificate and generate it
        var signatureFactory = new Asn1SignatureFactory(
            "SHA256WithRSA", privateKey, random);
        var certificate = certificateGenerator.Generate(signatureFactory);
        
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
            "*." + domain,
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