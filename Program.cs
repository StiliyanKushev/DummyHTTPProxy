# if true 
using MyHttpProxy;

// gather information about the system at runtime
SystemIdentifier.GatherInformation();

// inject/validate our custom CA
CAInjector.ValidateOrInject();

// Register HttpClient as a service
var builder = WebApplication.CreateBuilder(args);
builder.Services.AddHttpClient();

// Configure Kestrel
builder.WebHost.ConfigureKestrel(KestrelConfiguration.ConfigureServer);

// run the http proxy handler
var app = builder.Build();
app.Run(Listener.RetrieveConnectionListener(app));
app.Run();

#endif

#if false

using Org.BouncyCastle.Asn1;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;
using Org.BouncyCastle.X509;
using System;
using System.IO;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.Utilities;

public class BouncyCastleCertificateGenerator
{
    private static string BC_PROVIDER = "BC";
    private static string KEY_ALGORITHM = "RSA";
    private static string SIGNATURE_ALGORITHM = "SHA256WithRSA";

    public static void Main(string[] args)
    {
        SecureRandom secureRandom = new SecureRandom();
        RsaKeyPairGenerator generator = new RsaKeyPairGenerator();
        generator.Init(new KeyGenerationParameters(secureRandom, 2048));

        // Generate root certificate
        AsymmetricCipherKeyPair rootKeyPair = generator.GenerateKeyPair();

        BigInteger rootSerialNum = BigIntegers.CreateRandomInRange(
            BigInteger.One,                                
            BigInteger.ValueOf(long.MaxValue), secureRandom);    
        
        X509V1CertificateGenerator rootCertGen = new X509V1CertificateGenerator();
        rootCertGen.SetSerialNumber(rootSerialNum);
        rootCertGen.SetIssuerDN(new X509Name("CN=root-cert"));
        rootCertGen.SetNotBefore(DateTime.Now.AddDays(-1));
        rootCertGen.SetNotAfter(DateTime.Now.AddYears(1));
        rootCertGen.SetSubjectDN(new X509Name("CN=root-cert"));
        rootCertGen.SetPublicKey(rootKeyPair.Public);
        
        var signatureFactoryRoot = new Asn1SignatureFactory(
            "SHA256WithRSA", rootKeyPair.Private, secureRandom);
        
        Org.BouncyCastle.X509.X509Certificate rootCert = rootCertGen.Generate(signatureFactoryRoot);
        File.WriteAllBytes("root-cert.cer", rootCert.GetEncoded());

        // Generate child certificate
        AsymmetricCipherKeyPair childKeyPair = generator.GenerateKeyPair();
        BigInteger childSerialNum = new BigInteger(secureRandom.NextLong().ToString());

        X509V3CertificateGenerator childCertGen = new X509V3CertificateGenerator();
        childCertGen.SetSerialNumber(childSerialNum);
        childCertGen.SetIssuerDN(new X509Name("CN=root-cert"));
        childCertGen.SetNotBefore(DateTime.Now.AddDays(-1));
        childCertGen.SetNotAfter(DateTime.Now.AddYears(1));
        childCertGen.SetSubjectDN(new X509Name("CN=child-cert"));
        childCertGen.SetPublicKey(childKeyPair.Public);
        
        var signatureFactoryChild = new Asn1SignatureFactory(
            "SHA256WithRSA", rootKeyPair.Private, secureRandom);
        
        Org.BouncyCastle.X509.X509Certificate childCert = childCertGen.Generate(signatureFactoryChild);

        File.WriteAllBytes("child-cert.cer", childCert.GetEncoded());
    }
}

#endif