using System.Collections.Concurrent;
using System.Net;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace MyHttpProxy;

public abstract class CertificateGeneration
{
    /// <summary>
    /// Growing memory cache of certificates per domain name.
    /// </summary>
    private static readonly ConcurrentDictionary<string,
        (X509Certificate2, X509Certificate2Collection)> CertificateCache = new ();

    /// <summary>
    /// All of the CA attributes.
    /// </summary>
    public const string CaCommonName              = "MyDummyCommonName";
    public const string CaCountryName             = "AQ"; 
    public const string CaStateName               = "Antartica"; 
    public const string CaLocalityName            = "Antartica"; 
    public const string CaOrganizationName        = CaCommonName; 
    public const string CaOrganizationalUnitName  = "Local Certificate Authority";
    public const string CaFriendlyName            = "Hoody Local Security";
    public const string CaEmailAddress            = "ca@hoody.local";

    /// <summary>
    /// All of the child certificate attributes.
    /// </summary>
    private const string CertCountryName           = CaCommonName;
    private const string CertStateName             = CaStateName;
    private const string CertLocalityName          = CaLocalityName;
    private const string CertOrganizationName      = CaCommonName;
    private const string CertOrganizationUnitName  = CaCommonName;
    private static Func<string, string> CertCommonName = domain => "*." + domain;
    
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

        var distinguishedName = new X500DistinguishedName(
            string.Join(", ", new List<string>
            {
                $"CN={CaCommonName}", 
                $"C={CaCountryName}",
                $"ST={CaStateName}",
                $"L={CaLocalityName}", 
                $"O={CaOrganizationName}", 
                $"OU={CaOrganizationalUnitName}",
                $"E={CaEmailAddress}"
            }));

        var certRequest = new CertificateRequest(
            distinguishedName,
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
                hasPathLengthConstraint: false,
                pathLengthConstraint: 1,
                critical: true));

        var notBefore = DateTimeOffset.UtcNow.AddMonths(-1);
        var notAfter = notBefore.AddYears(4);

        var cert = certRequest.CreateSelfSigned(notBefore, notAfter);

        // Set the Ca's friendly name on windows.
        if (SystemIdentifier.GatheredInformation.OsPlatform
            == OSPlatform.Windows)
        {
            cert.FriendlyName = CaFriendlyName;
        }
        
        // Get Private Key
        var privateKeyBytes = cert.GetRSAPrivateKey()!.ExportPkcs8PrivateKey();
        var privateKey = PrivateKeyBytesToString(privateKeyBytes);
        
        // Get certificate in PEM format
        var certificateText = X509Certificate2ToString(cert);

        return (privateKey, certificateText);
    }

    /// <summary>
    /// Generates a valid trusted certificate based on a given domain name.
    /// </summary>
    public static (
        X509Certificate2 certificate,
        X509Certificate2Collection collection
        ) GenerateCertificate(string domainName)
    {
        // try to retrieve a cached certificate before generating
        if (CertificateCache.TryGetValue(domainName, out var cached))
        {
            return cached;
        }
        
        Console.WriteLine($"[CERTIFICATE GENERATION FOR]: {domainName}");
        
        var rsa = RSA.Create(KeySizeInBytes);
        
        var distinguishedName = new X500DistinguishedName(
            string.Join(", ", new List<string>
            {
                $"C={CertCountryName}",
                $"ST={CertStateName}",
                $"L={CertLocalityName}", 
                $"O={CertOrganizationName}", 
                $"OU={CertOrganizationUnitName}",
                $"CN={CertCommonName(domainName)}"
            }));

        var certRequest = new CertificateRequest(
            distinguishedName,
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
        if (domainName.Length > 0)
        {
            var subjectAlternativeNames = new[]
            {
                "www." + domainName, 
                "*." + domainName,
                domainName
            };
            var subjectAlternativeIPs = new[]
            {
                IPAddress.Parse("127.0.0.1"), 
                IPAddress.Parse("0.0.0.0")
            };
            var subjectAlternativeNamesExtension = 
                BuildSubjectAlternativeNameExtension(
                    subjectAlternativeNames, subjectAlternativeIPs);
            certRequest.CertificateExtensions.Add(
                subjectAlternativeNamesExtension);
        }
        
        var notBefore = DateTimeOffset.UtcNow.AddDays(-1);
        var notAfter = notBefore.AddYears(2);

        var serialNumber = new byte[20];
        using (var rng = RandomNumberGenerator.Create())
        {
            rng.GetBytes(serialNumber);
        }
        
        // Ensure the serial number is non-negative
        serialNumber[0] &= 0x7F;
        
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
        
        // Convert the CA certificate and the server
        // certificate into a .NET Certificate2Collection.
        var collection = new X509Certificate2Collection
        {
            domainCertWithKey,   // add server certificate
            CaPemCertificate     // add CA certificate
        };
        
        // Convert the signed certificate into an exportable Pfx
        var signedCertificate = CreateCertificateWithChain(collection);

        // Simple error checking
#if DEBUG
        var hasPrivateKey = signedCertificate.HasPrivateKey;
        var verified = signedCertificate.Verify();
        Console.WriteLine($"[CERTIFICATE HAS PRIVATE KEY]: {hasPrivateKey}");
        Console.WriteLine($"[CERTIFICATE VERIFIED]: {verified}");

        if (domainName.Length > 0)
        {
            var matchesHostname = signedCertificate
                .MatchesHostname(domainName);
            Console.WriteLine($"[CERTIFICATE MATCHES HOSTNAME]: {
                matchesHostname}");
        }

        // try to get the reason why it can't be verified.
        if (verified == false)
        {
            var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;   
            
            try
            {
                var chainBuilt = chain.Build(signedCertificate);

                // Print out the length of the certificate chain
                Console.WriteLine($"[CERT CHAIN LENGTH]: {
                    chain.ChainElements.Count}");
                
                if (chainBuilt == false)
                    foreach (var chainStatus in chain.ChainStatus)
                        Console.WriteLine("Chain error: {0} {1}", 
                            chainStatus.Status, 
                            chainStatus.StatusInformation);
            }
            catch (Exception ex)
            {
                Console.WriteLine(ex.ToString());
            }
        }
#endif
        
        // insert generated certificate into the cache.
        CertificateCache.TryAdd(domainName, (signedCertificate, collection));
        
        return (signedCertificate, collection);
    }
    
    private static X509Certificate2 CreateCertificateWithChain(
        X509Certificate2Collection collection)
    {
        // Then, export the collection into a PFX byte array.
        // The private key is included as well.
        var pfxData = collection.Export(X509ContentType.Pfx, ""); // no password

        // Create and return a new X509Certificate2 from the PFX data.
        // This certificate includes the private key and the full chain.
        return new X509Certificate2(pfxData!, "", 
            X509KeyStorageFlags.PersistKeySet | X509KeyStorageFlags.Exportable);
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