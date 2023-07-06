using MyHttpProxy;

// gather information about the system at runtime
SystemIdentifier.GatherInformation();

// inject/validate our custom CA
CaInjector.ValidateOrInject();

// Register HttpClient as a service
var builder = WebApplication.CreateBuilder(args);
builder.Services.AddHttpClient();

// Configure Kestrel
builder.WebHost.ConfigureKestrel(KestrelConfiguration.ConfigureServer);

// run the http proxy handler
var app = builder.Build();
app.Run(Listener.RetrieveConnectionListener(app));
app.Run();