using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using Microsoft.AspNetCore.Server.Kestrel.Core;

using Org.BouncyCastle.Security;
using Org.BouncyCastle.Asn1.X509;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Generators;
using Org.BouncyCastle.Crypto.Operators;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.Math;
using Org.BouncyCastle.X509;
using Org.BouncyCastle.Utilities;

RSA ConvertToRSA(AsymmetricCipherKeyPair keyPair)
{
    RsaPrivateCrtKeyParameters privateKeyParams = (RsaPrivateCrtKeyParameters)keyPair.Private;

    RSAParameters rsaParameters = new RSAParameters
    {
        Modulus = privateKeyParams.Modulus.ToByteArrayUnsigned(),
        Exponent = privateKeyParams.PublicExponent.ToByteArrayUnsigned(),
        P = privateKeyParams.P.ToByteArrayUnsigned(),
        Q = privateKeyParams.Q.ToByteArrayUnsigned(),
        DP = privateKeyParams.DP.ToByteArrayUnsigned(),
        DQ = privateKeyParams.DQ.ToByteArrayUnsigned(),
        InverseQ = privateKeyParams.QInv.ToByteArrayUnsigned(),
        D = privateKeyParams.Exponent.ToByteArrayUnsigned(),
    };

    RSA rsa = RSA.Create();
    rsa.ImportParameters(rsaParameters);

    return rsa;
}

X509Certificate2 GenerateCertificate(string subjectName)
{
    var random = new SecureRandom();
    var certificateGenerator = new X509V3CertificateGenerator();

    var serialNumber = BigIntegers.CreateRandomInRange(BigInteger.One, BigInteger.ValueOf(long.MaxValue), random);
    certificateGenerator.SetSerialNumber(serialNumber);

    var dirName = new X509Name($"CN={subjectName}");
    certificateGenerator.SetIssuerDN(dirName);
    certificateGenerator.SetSubjectDN(dirName);

    certificateGenerator.SetNotBefore(DateTime.UtcNow.Date);
    certificateGenerator.SetNotAfter(DateTime.UtcNow.Date.AddYears(1));

    var keyGenerationParameters = new KeyGenerationParameters(random, 2048);

    var keyPairGenerator = new RsaKeyPairGenerator();
    keyPairGenerator.Init(keyGenerationParameters);

    var subjectKeyPair = keyPairGenerator.GenerateKeyPair();
    certificateGenerator.SetPublicKey(subjectKeyPair.Public);

    var issuerKeyPair = subjectKeyPair;
    var signatureFactory = new Asn1SignatureFactory("SHA256WithRSA", issuerKeyPair.Private, random);
    var certificate = certificateGenerator.Generate(signatureFactory);

    byte[] certData = certificate.GetEncoded();
    RSA rsa = ConvertToRSA(subjectKeyPair);
    X509Certificate2 dotNetCertificate = new X509Certificate2(certData).CopyWithPrivateKey(rsa);

    return dotNetCertificate;
}

var builder = WebApplication.CreateBuilder(args);

// Register HttpClient as a service
builder.Services.AddHttpClient();

// Configure Kestrel
builder.WebHost.ConfigureKestrel(serverOptions =>
{
    serverOptions.ConfigureHttpsDefaults(co =>
    {
        co.ServerCertificateSelector = (context, name) =>
        {
            if (string.IsNullOrWhiteSpace(name))
            {
                return null;
            }

            return GenerateCertificate(name);
        };
    });
    serverOptions.ListenAnyIP(5001, listenOptions =>
    {
        listenOptions.Protocols = HttpProtocols.Http1AndHttp2;
        listenOptions.UseHttps();
    });
});

var app = builder.Build();

app.Run(async context =>
{
    // Build the destination URL
    var destinationUrl = new UriBuilder
    {
        Scheme = context.Request.Scheme,
        Host = context.Request.Host.Host,
        Path = context.Request.Path,
        Query = context.Request.QueryString.ToString()
    }.Uri;

    // Use HttpClient to send the request
    var httpClient = app.Services.GetRequiredService<IHttpClientFactory>().CreateClient();
    var proxyRequest = new HttpRequestMessage();
    var requestMethod = context.Request.Method;
    if (!HttpMethods.IsGet(requestMethod) &&
        !HttpMethods.IsHead(requestMethod) &&
        !HttpMethods.IsDelete(requestMethod) &&
        !HttpMethods.IsTrace(requestMethod))
    {
        var streamContent = new StreamContent(context.Request.Body);
        proxyRequest.Content = streamContent;
    }

    // Copy the request headers
    foreach (var header in context.Request.Headers)
    {
        proxyRequest.Headers.TryAddWithoutValidation(header.Key, header.Value.ToArray());
    }

    proxyRequest.Headers.Host = destinationUrl.Host;
    proxyRequest.RequestUri = destinationUrl;
    proxyRequest.Method = new HttpMethod(context.Request.Method);

    using var responseMessage = await httpClient.SendAsync(proxyRequest, HttpCompletionOption.ResponseHeadersRead, context.RequestAborted);

    context.Response.StatusCode = (int)responseMessage.StatusCode;
    foreach (var header in responseMessage.Headers)
    {
        context.Response.Headers[header.Key] = header.Value.ToArray();
    }

    foreach (var header in responseMessage.Content.Headers)
    {
        context.Response.Headers[header.Key] = header.Value.ToArray();
    }

    // Send the response body to the client
    await responseMessage.Content.CopyToAsync(context.Response.Body);
});

app.Run();