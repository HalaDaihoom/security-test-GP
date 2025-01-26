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
        _httpClient.BaseAddress = new Uri("http://localhost:8080"); // Update with actual ZAP address
        _httpClient.DefaultRequestHeaders.Add("X-ZAP-API-Key", ApiKey); // Include API key in headers
        _httpClient.Timeout = TimeSpan.FromMinutes(10); // Longer timeout for scans
    }

    public async Task<string> StartSpiderAsync(string url, CancellationToken cancellationToken = default)
    {
        try
        {
            var response = await _httpClient.GetAsync($"/JSON/spider/action/scan/?url={Uri.EscapeDataString(url)}", cancellationToken);
            response.EnsureSuccessStatusCode();
            var content = await response.Content.ReadAsStringAsync();
            var spiderId = JObject.Parse(content)["scan"]?.ToString();

            if (string.IsNullOrEmpty(spiderId))
                throw new Exception("Spider ID not found in the response.");

            return spiderId;
        }
        catch (Exception ex)
        {
            throw new Exception($"Failed to start spider for URL {url}: {ex.Message}", ex);
        }
    }

    public async Task<string> GetSpiderStatusAsync(string spiderId, CancellationToken cancellationToken = default)
    {
        try
        {
            var response = await _httpClient.GetAsync($"/JSON/spider/view/status/?scanId={spiderId}", cancellationToken);
            response.EnsureSuccessStatusCode();
            var content = await response.Content.ReadAsStringAsync();
            return JObject.Parse(content)["status"]?.ToString();
        }
        catch (Exception ex)
        {
            throw new Exception($"Failed to get spider status for spiderId {spiderId}: {ex.Message}", ex);
        }
    }

    public async Task<int> StartScanAsync(string url, CancellationToken cancellationToken = default)
    {
        try
        {
            var response = await _httpClient.GetAsync($"/JSON/ascan/action/scan/?url={Uri.EscapeDataString(url)}", cancellationToken);
            response.EnsureSuccessStatusCode();
            var content = await response.Content.ReadAsStringAsync();
            var scanId = JObject.Parse(content)["scan"]?.ToString();

            if (string.IsNullOrEmpty(scanId))
                throw new Exception("Scan ID not found in the response.");

            if (!int.TryParse(scanId, out int zapScanId))
                throw new Exception($"Invalid Scan ID returned: {scanId}");

            return zapScanId;
        }
        catch (Exception ex)
        {
            throw new Exception($"Failed to start scan for URL {url}: {ex.Message}", ex);
        }
    }

    public async Task<string> GetScanStatusAsync(int scanId, CancellationToken cancellationToken = default)
    {
        try
        {
            var response = await _httpClient.GetAsync($"/JSON/ascan/view/status/?scanId={scanId}", cancellationToken);
            response.EnsureSuccessStatusCode();
            var content = await response.Content.ReadAsStringAsync();
            return JObject.Parse(content)["status"]?.ToString();
        }
        catch (Exception ex)
        {
            throw new Exception($"Failed to get scan status for scanId {scanId}: {ex.Message}", ex);
        }
    }

    public async Task<string> GetScanResultsAsync(string baseUrl, CancellationToken cancellationToken)
    {
        try
        {
            if (string.IsNullOrEmpty(baseUrl))
                throw new ArgumentException("Base URL is required to fetch scan results.");

            string apiUrl = $"/JSON/alert/view/alerts/?baseurl={Uri.EscapeDataString(baseUrl)}";

            var response = await _httpClient.GetAsync(apiUrl, cancellationToken);
            response.EnsureSuccessStatusCode();

            return await response.Content.ReadAsStringAsync(cancellationToken);
        }
        catch (Exception ex)
        {
            throw new Exception($"Failed to fetch scan results for baseUrl {baseUrl}: {ex.Message}", ex);
        }
    }
}
