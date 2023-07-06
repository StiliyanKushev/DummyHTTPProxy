using Microsoft.AspNetCore.Server.Kestrel.Core;

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
        ConfigureSniCallback(serverOptions);
        
        // finally listen on the specified port
        serverOptions.ListenAnyIP(5001, listenOptions =>
        {
            listenOptions.Protocols = HttpProtocols.Http1AndHttp2;
            listenOptions.UseHttps();
        });
    }

    private static void ConfigureSniCallback(KestrelServerOptions serverOptions)
    {
        serverOptions.ConfigureHttpsDefaults(co =>
        {
            // note: even if name is null/empty we still want to generate
            // note: a certificate. Example: `openssl s_client -connect`
            // note: sends an empty name.
            co.ServerCertificateSelector = (context, name) => 
                CertificateGeneration.GenerateCertificate(name);
        });
    }
}