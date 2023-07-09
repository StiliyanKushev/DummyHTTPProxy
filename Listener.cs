using System;
using System.Collections.Concurrent;
using System.Linq;
using System.Net.Http;
using System.Net.WebSockets;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace MyHttpProxy;

public abstract class Listener
{
    private static WebApplication _appReference = null!;
    private static IHttpClientFactory _clientFactory = null!;

    /// <summary>
    /// Create an http client pool, one for each domain.
    /// </summary>
    private static readonly ConcurrentDictionary<string, HttpClient>
        ClientPool = new();
    
    private static HttpClient GetClientFromPool(string domainName)
    {
        return ClientPool.GetOrAdd(domainName, 
            _ => _clientFactory.CreateClient());
    }
    
    /// <summary>
    /// Bootloader function used to store a reference to the app and attack
    /// the actual connection listener.
    /// </summary>
    /// <param name="app"></param>
    public static RequestDelegate RetrieveConnectionListener(WebApplication app)
    {
        _appReference = app;
        _clientFactory = _appReference.Services
            .GetRequiredService<IHttpClientFactory>();
        return ConnectionListener;
    }
    
    /// <summary>
    /// Connection Listener that proxies all incoming requests.
    /// </summary>
    /// <param name="context"></param>
    private static async Task ConnectionListener(HttpContext context)
    {
        try
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
            
            // Check if the request is a WebSocket connection
            if (context.WebSockets.IsWebSocketRequest)
            {
                using var clientWebSocket = new ClientWebSocket();
                using var browserWebSocket = await context.WebSockets
                    .AcceptWebSocketAsync();
        
                // Here, establish a new WebSocket connection to the
                // destination and start transferring message between
                // clientWebSocket and serverWebSocket.
                await WebSocketListener(
                    clientWebSocket, 
                    browserWebSocket,
                    destinationUrl);
                return;
            }

            // Use HttpClient to send the request
            var httpClient = GetClientFromPool(destinationUrl.Host);

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
            response.Body.Close();
        }
        catch (Exception e)
        {
            Console.WriteLine(e);
        }
    }


    /// <summary>
    /// Websocket proxy connection handler.
    /// </summary>
    private static async Task WebSocketListener(ClientWebSocket clientWebSocket,
        WebSocket browserWebSocket, Uri targetUri)
    {
        // Connect to the destination server
        await clientWebSocket.ConnectAsync(targetUri, CancellationToken.None);
    
        var buffer = new byte[8192];

        // Start two tasks that will act asynchronously: one will forward all messages from browser to server, 
        // the other from server to browser
        var browserToServerTask = ForwardWebSocketMessage(browserWebSocket, clientWebSocket, buffer, "Browser", "Server");
        var serverToBrowserTask = ForwardWebSocketMessage(clientWebSocket, browserWebSocket, buffer, "Server", "Browser");

        // Wait for any of these tasks to complete. If one fails, other will be cancelled.
        var firstTask = await Task.WhenAny(browserToServerTask, serverToBrowserTask);

        // If the task has faulted, propagate the exception. This will result in the other task being cancelled.
        await firstTask;

        // Wait for the other task to complete
        await Task.WhenAll(browserToServerTask, serverToBrowserTask);
    }
    
    private static async Task ForwardWebSocketMessage(WebSocket source, WebSocket destination, byte[] buffer, string sourceName, string destinationName)
    {
        while (true)
        {
            var result = await source.ReceiveAsync(new ArraySegment<byte>(buffer), CancellationToken.None);

            if (result.MessageType == WebSocketMessageType.Close)
            {
                await destination.CloseAsync(result.CloseStatus ?? WebSocketCloseStatus.NormalClosure, result.CloseStatusDescription, CancellationToken.None);
                Console.WriteLine($"{sourceName} sent close message. Close status: {result.CloseStatus}. Description: {result.CloseStatusDescription}.");
                break;
            }
            else
            {
                // Write the message received from the source to the destination
                await destination.SendAsync(new ArraySegment<byte>(buffer, 0, result.Count), result.MessageType, result.EndOfMessage, CancellationToken.None);
            }
        }
    }
}