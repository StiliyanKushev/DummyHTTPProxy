using MyHttpProxy;

var builder = WebApplication.CreateBuilder(args);

// Register HttpClient as a service
builder.Services.AddHttpClient();

// Configure Kestrel
builder.WebHost.ConfigureKestrel(KestrelConfiguration.ConfigureServer);

// run the http proxy handler
var app = builder.Build();
app.Run(Listener.RetrieveConnectionListener(app));
app.Run();