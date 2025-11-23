using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json;
using Microsoft.Extensions.Configuration;


public class ZapService
{
    private readonly HttpClient _httpClient;
    private readonly string _apiKey;

    public ZapService(HttpClient httpClient, IConfiguration configuration)
    {
        _httpClient = httpClient;
        _httpClient.BaseAddress = new Uri(configuration["Zap:BaseUrl"]);
        _apiKey = configuration["Zap:ApiKey"];
        _httpClient.DefaultRequestHeaders.Add("X-ZAP-API-Key", _apiKey);
        _httpClient.Timeout = TimeSpan.FromMinutes(20); 
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

    public async Task WaitForAlertsToSettleAsync(string baseUrl, int expectedMinimumCount = 1, int maxRetries = 10, int delayBetweenRetriesMs = 3000, CancellationToken cancellationToken = default)
    {
        int previousCount = 0;

        for (int i = 0; i < maxRetries; i++)
        {
            var response = await _httpClient.GetAsync($"/JSON/alert/view/alertsSummary/?baseurl={Uri.EscapeDataString(baseUrl)}", cancellationToken);
            response.EnsureSuccessStatusCode();
            var content = await response.Content.ReadAsStringAsync();
            var summary = JObject.Parse(content)["alertsSummary"] as JObject;

            int currentCount = 0;
            if (summary != null)
            {
                foreach (var item in summary)
                {
                    if (int.TryParse(item.Value?.ToString(), out int count))
                    {
                        currentCount += count;
                    }
                }
            }

            if (currentCount >= expectedMinimumCount && currentCount == previousCount)
            {
                // Alerts count is stable
                return;
            }

            previousCount = currentCount;
            await Task.Delay(delayBetweenRetriesMs, cancellationToken);
        }

        // Optional: throw if alerts never settled
        throw new TimeoutException("ZAP alerts did not settle in time.");
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


