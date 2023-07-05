namespace MyHttpProxy;

public abstract class Listener
{
    private static WebApplication _appReference;
    
    /// <summary>
    /// Bootloader function used to store a reference to the app and attack
    /// the actual connection listener.
    /// </summary>
    /// <param name="app"></param>
    public static RequestDelegate RetrieveConnectionListener(WebApplication app)
    {
        _appReference = app;
        return ConnectionListener;
    }
    
    /// <summary>
    /// Connection Listener that proxies all incoming requests.
    /// </summary>
    /// <param name="context"></param>
    private static async Task ConnectionListener(HttpContext context)
    {
        var request = context.Request;
        var response = context.Response;
        
         // Build the destination URL
         var destinationUrl = new UriBuilder
         {
             Scheme = request.Scheme,
             Host = request.Host.Host,
             Path = request.Path,
             Query = request.QueryString.ToString()
         }.Uri;
         
         // Use HttpClient to send the request
         var httpClient = _appReference.Services
             .GetRequiredService<IHttpClientFactory>().CreateClient();
         
         // prepare the http request message
         var proxyRequest = new HttpRequestMessage();
         var requestMethod = request.Method;
         if (!HttpMethods.IsGet(requestMethod) &&
             !HttpMethods.IsHead(requestMethod) &&
             !HttpMethods.IsDelete(requestMethod) &&
             !HttpMethods.IsTrace(requestMethod))
         {
             var streamContent = new StreamContent(request.Body);
             proxyRequest.Content = streamContent;
         }
         
         // Copy the request headers
         foreach (var header in request.Headers)
         {
             proxyRequest.Headers.TryAddWithoutValidation(
                 header.Key, header.Value.ToArray());
         }
         
         // prepare the correct request destination
         proxyRequest.Headers.Host = destinationUrl.Host;
         proxyRequest.RequestUri = destinationUrl;
         proxyRequest.Method = new HttpMethod(request.Method);
         
         // fire the request to the endpoint
         using var responseMessage = await httpClient.SendAsync(
             proxyRequest, 
             HttpCompletionOption.ResponseHeadersRead, 
             context.RequestAborted);
         
         // set the status code and response headers
         response.StatusCode = (int)responseMessage.StatusCode;
         foreach (var header in responseMessage.Headers)
         {
             response.Headers[header.Key] = header.Value.ToArray();
         }
         foreach (var header in responseMessage.Content.Headers)
         {
             response.Headers[header.Key] = header.Value.ToArray();
         }
         
         // Send the response body to the client
         await responseMessage.Content.CopyToAsync(response.Body);
    }
}