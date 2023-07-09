using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.WebSockets;
using Microsoft.Extensions.DependencyInjection;
using MyHttpProxy;

// gather information about the system at runtime
SystemIdentifier.GatherInformation();

// inject/validate our custom CA
CaInjector.ValidateOrInject();

// Register HttpClient as a service
var builder = WebApplication.CreateBuilder(args);
builder.Services.AddResponseCaching();
builder.Services.AddHttpClient();
builder.Services.AddWebSockets(_ => { });

// Configure Kestrel
builder.WebHost.ConfigureKestrel(KestrelConfiguration.ConfigureServer);

// run the http proxy handler
var app = builder.Build();
app.UseResponseCaching();
app.Run(Listener.RetrieveConnectionListener(app));
app.Run();