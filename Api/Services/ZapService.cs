using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json;

public class ZapService
{
    private readonly HttpClient _httpClient;
    private const string ApiKey = "gp7ihhmfhpjikk6clu1uhm3519";

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

    public async Task<int> StartScanAsync(string url, CancellationToken cancellationToken = default)
    {
        var response = await _httpClient.GetAsync($"/JSON/ascan/action/scan/?url={Uri.EscapeDataString(url)}", cancellationToken);
        response.EnsureSuccessStatusCode();
        var content = await response.Content.ReadAsStringAsync();
        var scanId = JObject.Parse(content)["scan"]?.ToString();

        if (string.IsNullOrEmpty(scanId))
            throw new Exception("Scan ID not found in the response.");

        // Convert scanId to int
        if (!int.TryParse(scanId, out int zapScanId))
            throw new Exception("Scan ID is not a valid integer.");

        return zapScanId; // Return as int
    }

    public async Task<string> GetScanStatusAsync(int scanId, CancellationToken cancellationToken = default)
    {
        var timestamp = DateTime.UtcNow.Ticks.ToString();
        var response = await _httpClient.GetAsync($"/JSON/ascan/view/status/?scanId={scanId}&_={timestamp}", cancellationToken);
        response.EnsureSuccessStatusCode();
        var content = await response.Content.ReadAsStringAsync();
        return JObject.Parse(content)["status"]?.ToString();
    }

    public async Task<string> GetScanResultsAsync(int scanId, CancellationToken cancellationToken)
    {
        string apiUrl = $"http://localhost:8080/JSON/alert/view/alerts/?baseurl=&scanId={scanId}";

        var response = await _httpClient.GetAsync(apiUrl, cancellationToken);
        response.EnsureSuccessStatusCode();

        return await response.Content.ReadAsStringAsync(cancellationToken);
    }
}


// // // using System;
// // // using System.Net.Http;
// // // using System.Threading;
// // // using System.Threading.Tasks;
// // // using Newtonsoft.Json.Linq;

// // // public class ZapService
// // // {
// // //     private readonly HttpClient _httpClient;
// // //     private const string ApiKey = "gp7ihhmfhpjikk6clu1uhm3519"; // Replace with your actual ZAP API key

// // //     public ZapService(HttpClient httpClient)
// // //     {
// // //         _httpClient = httpClient;
// // //         _httpClient.BaseAddress = new Uri("http://localhost:8080"); // Set to ZAP's actual base address
// // //         _httpClient.DefaultRequestHeaders.Add("X-ZAP-API-Key", ApiKey); // Include API key in headers
// // //         _httpClient.Timeout = TimeSpan.FromMinutes(10); // Set a longer timeout
// // //     }

// // //     public async Task<string> StartSpiderAsync(string url, CancellationToken cancellationToken = default)
// // //     {
// // //         var response = await _httpClient.GetAsync($"/JSON/spider/action/scan/?url={Uri.EscapeDataString(url)}", cancellationToken);
// // //         response.EnsureSuccessStatusCode();
// // //         var content = await response.Content.ReadAsStringAsync();
// // //         var spiderId = JObject.Parse(content)["scan"]?.ToString();

// // //         if (string.IsNullOrEmpty(spiderId))
// // //             throw new Exception("Spider ID not found in the response.");

// // //         return spiderId;
// // //     }

// // //     public async Task<string> GetSpiderStatusAsync(string spiderId, CancellationToken cancellationToken = default)
// // //     {
// // //         var timestamp = DateTime.UtcNow.Ticks.ToString();
// // //         var response = await _httpClient.GetAsync($"/JSON/spider/view/status/?scanId={spiderId}&_={timestamp}", cancellationToken);
// // //         response.EnsureSuccessStatusCode();
// // //         var content = await response.Content.ReadAsStringAsync();
// // //         return JObject.Parse(content)["status"]?.ToString();
// // //     }

// // //     public async Task<string> StartScanAsync(string url, CancellationToken cancellationToken = default)
// // //     {
// // //         var response = await _httpClient.GetAsync($"/JSON/ascan/action/scan/?url={Uri.EscapeDataString(url)}", cancellationToken);
// // //         response.EnsureSuccessStatusCode();
// // //         var content = await response.Content.ReadAsStringAsync();
// // //         var scanId = JObject.Parse(content)["scan"]?.ToString();

// // //         if (string.IsNullOrEmpty(scanId))
// // //             throw new Exception("Scan ID not found in the response.");

// // //         return scanId;
// // //     }

// // //     public async Task<string> GetScanStatusAsync(string scanId, CancellationToken cancellationToken = default)
// // //     {
// // //         var timestamp = DateTime.UtcNow.Ticks.ToString();
// // //         var response = await _httpClient.GetAsync($"/JSON/ascan/view/status/?scanId={scanId}&_={timestamp}", cancellationToken);
// // //         response.EnsureSuccessStatusCode();
// // //         var content = await response.Content.ReadAsStringAsync();
// // //         return JObject.Parse(content)["status"]?.ToString();
// // //     }

// // //     public async Task<string> GetScanResultsAsync(string scanId, CancellationToken cancellationToken = default)
// // //     {
// // //         var response = await _httpClient.GetAsync($"/JSON/core/view/alerts/?baseurl=&scanId={scanId}", cancellationToken);
// // //         response.EnsureSuccessStatusCode();
// // //         return await response.Content.ReadAsStringAsync();
// // //     }
// // // }
