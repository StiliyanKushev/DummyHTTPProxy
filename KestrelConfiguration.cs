using Microsoft.AspNetCore.Server.Kestrel.Core;

namespace MyHttpProxy;

public abstract class KestrelConfiguration
{
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
        serverOptions.ConfigureHttpsDefaults( co =>
        {
            co.ServerCertificateSelector = (context, name) => 
                string.IsNullOrWhiteSpace(name) ? null :
                    // generate a certificate based on domain name
                    CertificateGeneration.GenerateCertificate(name);
        });
    }
}