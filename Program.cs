using Microsoft.AspNetCore.WebSockets;
using MyHttpProxy;

// gather information about the system at runtime
SystemIdentifier.GatherInformation();

// inject/validate our custom CA
CaInjector.ValidateOrInject();

// Register HttpClient as a service
var builder = WebApplication.CreateBuilder(args);
builder.Services.AddResponseCaching();
builder.Services.AddWebSockets(_ => { });

// Add our custom default http client handler
Listener.AddCustomHttpClients(builder);

// Configure Kestrel
builder.WebHost.ConfigureKestrel(KestrelConfiguration.ConfigureServer);

// run the http proxy handler
var app = builder.Build();
app.UseResponseCaching();
app.UseWebSockets();
app.UseHttpsRedirection();
app.Run(Listener.RetrieveConnectionListener(app));
app.Run();
