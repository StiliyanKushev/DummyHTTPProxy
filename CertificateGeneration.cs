using System.Net;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace MyHttpProxy;

public abstract class CertificateGeneration
{
    /// <summary>
    /// The common name used in the injected CA
    /// </summary>
    public const string CaCommonName = "DummyCommonName";

    /// <summary>
    /// Used everytime we want to generate a key.
    /// </summary>
    public const int KeySizeInBytes = 4096;

    /// <summary>
    /// Creates a tuple of a private key and a self-signed certificate.
    /// </summary>
    public static (string privateKey, string certificateText) CreateCertificateAuthority()
    {
        var rsa = RSA.Create(KeySizeInBytes);

        var certRequest = new CertificateRequest(
            $"CN={CaCommonName}",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        certRequest.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.KeyCertSign |
                X509KeyUsageFlags.CrlSign, 
                critical: true));

        certRequest.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(
                certificateAuthority: true, 
                hasPathLengthConstraint: true,
                // note: important. If it's is zero we can't sign 
                // note: our dynamically generated certificates.
                pathLengthConstraint: 999,
                critical: true));

        var notBefore = DateTimeOffset.UtcNow.AddDays(-1);
        var notAfter = notBefore.AddYears(10);

        var cert = certRequest.CreateSelfSigned(notBefore, notAfter);

        // Get Private Key
        var privateKeyBytes = cert.GetRSAPrivateKey().ExportPkcs8PrivateKey();
        var privateKey = PrivateKeyBytesToString(privateKeyBytes);
        
        // Get certificate in PEM format
        var certificateText = X509Certificate2ToString(cert);

        return (privateKey, certificateText);
    }
    
    /// <summary>
    /// Generates a valid trusted certificate based on a given domain name.
    /// </summary>
    public static X509Certificate2 GenerateCertificate(string domainName)
    {
        Console.WriteLine($"[CERTIFICATE GENERATION FOR]: {domainName}");
        
        var rsa = RSA.Create(KeySizeInBytes);

        var certRequest = new CertificateRequest(
            $"CN={domainName}",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        certRequest.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.DataEncipherment |
                X509KeyUsageFlags.KeyEncipherment |
                X509KeyUsageFlags.DigitalSignature, 
                false));

        // Add the SubjectAlternativeName extension
        var subjectAlternativeNames = new[]
        {
            "www." + domainName, 
            "*." + domainName,
            "localhost"
        };
        var subjectAlternativeIPs = new[]
        {
            IPAddress.Parse("127.0.0.1"), 
            IPAddress.Parse("0.0.0.0")
        };
        var subjectAlternativeNamesExtension = 
            BuildSubjectAlternativeNameExtension(
                subjectAlternativeNames, subjectAlternativeIPs);
        certRequest.CertificateExtensions.Add(subjectAlternativeNamesExtension);
        
        var notBefore = DateTimeOffset.UtcNow.AddDays(-1);
        var notAfter = notBefore.AddYears(2);

        var serialNumber = new byte[20];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(serialNumber);
        }

        // Sign the certificate with the CA's private key
        var domainCert = certRequest.Create(
            CaPemCertificate.SubjectName,
            X509SignatureGenerator.CreateForRSA(
                CaPrivateKey, RSASignaturePadding.Pkcs1),
            notBefore,
            notAfter,
            serialNumber);

        // note: `CertificateRequest.Create` removes the Private Key
        // note: so we have to add it ourselves again like so:
        var domainCertWithKey = domainCert.CopyWithPrivateKey(rsa);
        
        // Convert the signed certificate into a X509Certificate2 instance
        var signedCertificate = new X509Certificate2(
            domainCertWithKey.Export(X509ContentType.Pfx), 
            (string)null, X509KeyStorageFlags.Exportable);

        // todo: remove. only for validating certificate with openssl.
        File.WriteAllText(Path.Join(Directory.GetCurrentDirectory(), 
            "test.crt"), X509Certificate2ToString(signedCertificate));
        
        return signedCertificate;

        // @see: https://github.com/dotnet/runtime/issues/45680
        // if (RuntimeInformation.IsOSPlatform(OSPlatform.Windows))
        // {
        //     return new X509Certificate2(
        //         dotNetCertificate.Export(
        //             X509ContentType.Pkcs12));
        // }
    }
    
    private static X509Extension BuildSubjectAlternativeNameExtension(
        string[] domainNames, IPAddress[] ipAddresses)
    {
        // Manually build the SubjectAlternativeName extension
        var sanBuilder = new SubjectAlternativeNameBuilder();
    
        foreach (var domainName in domainNames)
        {
            sanBuilder.AddDnsName(domainName);
        }
    
        foreach (var ipAddress in ipAddresses)
        {
            sanBuilder.AddIpAddress(ipAddress);
        }

        return sanBuilder.Build();
    }
    
    #region Retrieve the injected CA's private key and pem certificate.
    
    private static readonly RSA CaPrivateKey = 
        ParsePrivateKey(CaInjector.RetrievePrivateKey());

    private static readonly X509Certificate2 CaPemCertificate =
        ParseCertificate(CaInjector.RetrieveCertificate());

    private static X509Certificate2 ParseCertificate(string certificateText)
    {
        // Extract base64 part from the PEM format
        var base64Certificate = certificateText
            .Replace("-----BEGIN CERTIFICATE-----", "")
            .Replace("-----END CERTIFICATE-----", "")
            .Replace("\n", "")
            .Replace("\r", "");

        // Convert to byte array and create an X509Certificate2 instance
        var certificateBytes = Convert.FromBase64String(base64Certificate);
        return new X509Certificate2(certificateBytes);
    }
    
    private static RSA ParsePrivateKey(string privateKeyText)
    {
        // Convert CA's private key to RSA
        var caPrivateKeyBytes = Convert.FromBase64String(privateKeyText
            .Replace("-----BEGIN PRIVATE KEY-----", "")
            .Replace("-----END PRIVATE KEY-----", "")
            .Replace("\n", ""));
        
        var caRsa = RSA.Create();
        caRsa.ImportPkcs8PrivateKey(caPrivateKeyBytes, out _);
        return caRsa;
    }
    
    #endregion
    
    #region Convert .NET certificate and key objects to strings.
    
    private static string PrivateKeyBytesToString(byte[] privateKeyBytes)
    {
        return "-----BEGIN PRIVATE KEY-----\n" + 
               Convert.ToBase64String(
                   privateKeyBytes, 
                   Base64FormattingOptions.InsertLineBreaks) + 
               "\n-----END PRIVATE KEY-----";
    }

    private static string X509Certificate2ToString(X509Certificate2 cert)
    {
        return "-----BEGIN CERTIFICATE-----\r\n" + 
               Convert.ToBase64String(
                   cert.Export(X509ContentType.Cert), 
                   Base64FormattingOptions.InsertLineBreaks) +
               "\r\n-----END CERTIFICATE-----";
    }
    
    #endregion
}