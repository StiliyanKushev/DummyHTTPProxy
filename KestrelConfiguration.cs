using System.Net.Security;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Server.Kestrel.Core;
using Microsoft.AspNetCore.Server.Kestrel.Https;

namespace MyHttpProxy;

public abstract class KestrelConfiguration
{
    /// <summary>
    /// Configures the server to use HTTP2 and HTTP1.1 + HTTPS.
    /// It also configures a SNI Callback function to dynamically apply
    /// a generated certificate signed by our injected CA.
    /// </summary>
    public static void ConfigureServer(KestrelServerOptions serverOptions)
    {
        // finally listen on the specified port
        serverOptions.ListenAnyIP(5001, listenOptions =>
        {
            listenOptions.Protocols = HttpProtocols.Http1AndHttp2AndHttp3;
            listenOptions.UseHttps(new TlsHandshakeCallbackOptions
            {
                OnConnection = ConfigureSniCallback
            });
        });
    }

    private static ValueTask<SslServerAuthenticationOptions> 
        ConfigureSniCallback(TlsHandshakeCallbackContext context)
    {
        // get the domain name from client hello
        var domainName = context.ClientHelloInfo.ServerName;
        
        // generate a server certificate and the full-chain collection
        // including the CA
        var (
            certificate,
            collection) = CertificateGeneration.GenerateCertificate(domainName);
        
        // create a new ssl stream certificate context with the full-chain.
        var sslCertificateChain = SslStreamCertificateContext.Create(
            certificate, collection, offline: true);

        return new(new SslServerAuthenticationOptions
        {
            ServerCertificateContext = sslCertificateChain
        });
    }
}