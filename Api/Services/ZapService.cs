using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;

public class ZapService
{
    private readonly HttpClient _httpClient;
    private const string ApiKey = "42ikihbsjdjnmpq3ai47dpd8hi"; // Replace with your actual ZAP API key

    public ZapService(HttpClient httpClient)
    {
        _httpClient = httpClient;
        _httpClient.BaseAddress = new Uri("http://localhost:8080"); // Set to ZAP's actual base address
        _httpClient.DefaultRequestHeaders.Add("X-ZAP-API-Key", ApiKey); // Include API key in headers
        _httpClient.Timeout = TimeSpan.FromMinutes(10); // Set a longer timeout
    }

    public async Task<string> StartSpiderAsync(string url, CancellationToken cancellationToken = default)
    {
        var response = await _httpClient.GetAsync($"/JSON/spider/action/scan/?url={Uri.EscapeDataString(url)}", cancellationToken);
        response.EnsureSuccessStatusCode();
        var content = await response.Content.ReadAsStringAsync();
        var spiderId = JObject.Parse(content)["scan"]?.ToString();

        if (string.IsNullOrEmpty(spiderId))
            throw new Exception("Spider ID not found in the response.");

        return spiderId;
    }

    public async Task<string> GetSpiderStatusAsync(string spiderId, CancellationToken cancellationToken = default)
    {
        var timestamp = DateTime.UtcNow.Ticks.ToString();
        var response = await _httpClient.GetAsync($"/JSON/spider/view/status/?scanId={spiderId}&_={timestamp}", cancellationToken);
        response.EnsureSuccessStatusCode();
        var content = await response.Content.ReadAsStringAsync();
        return JObject.Parse(content)["status"]?.ToString();
    }

    public async Task<string> StartScanAsync(string url, CancellationToken cancellationToken = default)
    {
        var response = await _httpClient.GetAsync($"/JSON/ascan/action/scan/?url={Uri.EscapeDataString(url)}", cancellationToken);
        response.EnsureSuccessStatusCode();
        var content = await response.Content.ReadAsStringAsync();
        var scanId = JObject.Parse(content)["scan"]?.ToString();

        if (string.IsNullOrEmpty(scanId))
            throw new Exception("Scan ID not found in the response.");

        return scanId;
    }

    public async Task<string> GetScanStatusAsync(string scanId, CancellationToken cancellationToken = default)
    {
        var timestamp = DateTime.UtcNow.Ticks.ToString();
        var response = await _httpClient.GetAsync($"/JSON/ascan/view/status/?scanId={scanId}&_={timestamp}", cancellationToken);
        response.EnsureSuccessStatusCode();
        var content = await response.Content.ReadAsStringAsync();
        return JObject.Parse(content)["status"]?.ToString();
    }

    public async Task<string> GetScanResultsAsync(string scanId, CancellationToken cancellationToken = default)
    {
        var response = await _httpClient.GetAsync($"/JSON/core/view/alerts/?baseurl=&scanId={scanId}", cancellationToken);
        response.EnsureSuccessStatusCode();
        return await response.Content.ReadAsStringAsync();
    }
}



// using System;
// using System.Net.Http;
// using System.Threading;
// using System.Threading.Tasks;
// using Newtonsoft.Json.Linq;

// public class ZapService
// {
//     private readonly HttpClient _httpClient;
//     private const string ApiKey = "42ikihbsjdjnmpq3ai47dpd8hi"; // Replace with your actual ZAP API key

//     public ZapService(HttpClient httpClient)
//     {
//         _httpClient = httpClient;
//         _httpClient.BaseAddress = new Uri("http://localhost:8080"); // Set to ZAP's actual base address
//         _httpClient.DefaultRequestHeaders.Add("X-ZAP-API-Key", ApiKey); // Include API key in headers
//         _httpClient.Timeout = TimeSpan.FromMinutes(10); // Set a longer timeout (default is 100 seconds)
//     }

//     public async Task<string> StartSpiderAsync(string url, CancellationToken cancellationToken = default)
//     {
//         var response = await _httpClient.GetAsync($"/JSON/spider/action/scan/?url={Uri.EscapeDataString(url)}", cancellationToken);
//         response.EnsureSuccessStatusCode();
//         var content = await response.Content.ReadAsStringAsync();
//         var spiderId = JObject.Parse(content)["scan"]?.ToString();

//         if (string.IsNullOrEmpty(spiderId))
//         {
//             throw new Exception("Spider ID not found in the response.");
//         }

//         return spiderId;
//     }

//     public async Task<string> GetSpiderStatusAsync(string spiderId, CancellationToken cancellationToken = default)
//     {
//         var response = await _httpClient.GetAsync($"/JSON/spider/view/status/?scanId={spiderId}", cancellationToken);
//         response.EnsureSuccessStatusCode();
//         var content = await response.Content.ReadAsStringAsync();
//         return JObject.Parse(content)["status"]?.ToString();
//     }

//     public async Task<string> StartScanAsync(string url, CancellationToken cancellationToken = default)
//     {
//         var response = await _httpClient.GetAsync($"/JSON/ascan/action/scan/?url={Uri.EscapeDataString(url)}", cancellationToken);
//         response.EnsureSuccessStatusCode();
//         var content = await response.Content.ReadAsStringAsync();
//         var scanId = JObject.Parse(content)["scan"]?.ToString();

//         if (string.IsNullOrEmpty(scanId))
//         {
//             throw new Exception("Scan ID not found in the response.");
//         }

//         return scanId;
//     }

//     public async Task<string> GetScanStatusAsync(string scanId, CancellationToken cancellationToken = default)
//     {
//         var response = await _httpClient.GetAsync($"/JSON/ascan/view/status/?scanId={scanId}", cancellationToken);
//         response.EnsureSuccessStatusCode();
//         var content = await response.Content.ReadAsStringAsync();
//         return JObject.Parse(content)["status"]?.ToString();
//     }

//     public async Task<string> GetScanResultsAsync(string scanId, CancellationToken cancellationToken = default)
//     {
//         var response = await _httpClient.GetAsync($"/JSON/core/view/alerts/?baseurl=&scanId={scanId}", cancellationToken);
//         response.EnsureSuccessStatusCode();
//         return await response.Content.ReadAsStringAsync();
//     }
// }





// [run but set link manual]
// using System;
// using System.Net.Http;
// using System.Text;
// using System.Threading.Tasks;
// using Newtonsoft.Json.Linq;
// using Newtonsoft.Json;


// public class ZapService
// {
//     private readonly HttpClient _httpClient;
//     private const string ApiKey = "tku4lsd6a3lth0ku6bgepu637i"; 

//     public ZapService(HttpClient httpClient)
//     {
//         _httpClient = httpClient;
//         _httpClient.BaseAddress = new Uri("http://localhost:8080"); 
//         _httpClient.DefaultRequestHeaders.Add("X-ZAP-API-Key", ApiKey); 
//     }

    
//     public async Task<string> StartScanAsync(string url)
//     {
//         try
//         {
//             //var response = await _httpClient.GetAsync($"/JSON/ascan/action/scan/?url={Uri.EscapeDataString(url)}&apikey={ApiKey}");

//             var response = await _httpClient.GetAsync($"/JSON/ascan/action/scan/?url={Uri.EscapeDataString(url)}");
//             response.EnsureSuccessStatusCode(); // Throws if response status is not success
            
//             var content = await response.Content.ReadAsStringAsync();
//             var scanId = JObject.Parse(content)["scan"]?.ToString();

//             if (string.IsNullOrEmpty(scanId))
//             {
//                 throw new Exception("Scan ID not found in the response.");
//             }

//             return scanId;
//         }
//         catch (HttpRequestException httpRequestException)
//         {
//             Console.WriteLine($"HTTP Request Error: {httpRequestException.Message}");
//             throw new Exception("Error starting ZAP scan: " + httpRequestException.Message);
//         }
//         catch (Exception ex)
//         {
//             Console.WriteLine($"Error: {ex.Message}");
//             throw new Exception("Error starting ZAP scan: " + ex.Message);
//         }
//     }

    
//     public async Task<string> GetScanStatusAsync(string scanId)
//     {
//         try
//         {
//             var response = await _httpClient.GetAsync($"/JSON/ascan/view/status/?scanId={scanId}");
//             response.EnsureSuccessStatusCode();

//             var content = await response.Content.ReadAsStringAsync();
//             return JObject.Parse(content)["status"]?.ToString();
//         }
//         catch (HttpRequestException httpRequestException)
//         {
//             Console.WriteLine($"HTTP Request Error: {httpRequestException.Message}");
//             throw new Exception("Error retrieving scan status: " + httpRequestException.Message);
//         }
//         catch (Exception ex)
//         {
//             Console.WriteLine($"Error: {ex.Message}");
//             throw new Exception("Error retrieving scan status: " + ex.Message);
//         }
//     }

   
//     public async Task<string> GetScanResultsAsync(string scanId)
//     {
//         try
//         {
//             var response = await _httpClient.GetAsync($"/JSON/core/view/alerts/?baseurl=&scanId={scanId}");
//             response.EnsureSuccessStatusCode();

//             return await response.Content.ReadAsStringAsync();
//         }
//         catch (HttpRequestException httpRequestException)
//         {
//             Console.WriteLine($"HTTP Request Error: {httpRequestException.Message}");
//             throw new Exception("Error retrieving scan results: " + httpRequestException.Message);
//         }
//         catch (Exception ex)
//         {
//             Console.WriteLine($"Error: {ex.Message}");
//             throw new Exception("Error retrieving scan results: " + ex.Message);
//         }
//     }
   
// }