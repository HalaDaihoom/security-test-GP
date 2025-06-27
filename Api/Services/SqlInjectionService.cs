
using System;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;
using System.Collections.Generic;
using Microsoft.Extensions.Configuration;
using Api.Models.DTOs;  // Make sure this DTO exists

public class SqlInjectionService
{
    private readonly HttpClient _httpClient;
    private readonly string _apiKey;

    public SqlInjectionService(HttpClient httpClient, IConfiguration configuration)
    {
        _httpClient = httpClient;
        _httpClient.BaseAddress = new Uri(configuration["Zap:BaseUrl"]);
        _apiKey = configuration["Zap:ApiKey"];
        _httpClient.DefaultRequestHeaders.Add("X-ZAP-API-Key", _apiKey); // API key in header
        _httpClient.Timeout = TimeSpan.FromMinutes(100);
    }

    
    


    public async Task<string> StartSpiderAsync(string url, CancellationToken cancellationToken = default)
{
    try
    {
        // Add maxChildren=3 for 3 layers deep
        var spiderUrl = $"/JSON/spider/action/scan/?url={Uri.EscapeDataString(url)}&maxChildren=3";
        var response = await _httpClient.GetAsync(spiderUrl, cancellationToken);
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


    public async Task WaitForSpiderAsync(string spiderId)
    {
        try
        {
            string status;
            do
            {
                await Task.Delay(5000);
                var response = await _httpClient.GetAsync($"/JSON/spider/view/status/?scanId={spiderId}");
                response.EnsureSuccessStatusCode();
                var content = await response.Content.ReadAsStringAsync();
                status = JObject.Parse(content)["status"]?.ToString();
            } while (status != "100");
        }
        catch (Exception ex)
        {
            throw new Exception($"Failed while polling spider status: {ex.Message}", ex);
        }
    }

    public async Task<int> StartSqlInjectionScanAsync(string url)
    {
        try
        {
            var spiderId = await StartSpiderAsync(url);
            await WaitForSpiderAsync(spiderId);

            var response = await _httpClient.GetAsync($"/JSON/ascan/action/scan/?url={Uri.EscapeDataString(url)}");
            response.EnsureSuccessStatusCode();
            var content = await response.Content.ReadAsStringAsync();
            var scanId = JObject.Parse(content)["scan"]?.ToString();

            if (string.IsNullOrEmpty(scanId) || !int.TryParse(scanId, out int zapScanId))
                throw new Exception("Invalid Scan ID returned.");

            return zapScanId;
        }
        catch (Exception ex)
        {
            throw new Exception($"Failed to start SQL Injection scan for URL {url}: {ex.Message}", ex);
        }
    }

    public async Task WaitForScanCompletionAsync(int scanId)
    {
        try
        {
            string status;
            do
            {
                await Task.Delay(2000);
                var response = await _httpClient.GetAsync($"/JSON/ascan/view/status/?scanId={scanId}");
                response.EnsureSuccessStatusCode();
                var content = await response.Content.ReadAsStringAsync();
                status = JObject.Parse(content)["status"]?.ToString();
            } while (status != "100" );
        }
        catch (Exception ex)
        {
            throw new Exception($"Failed while polling scan status: {ex.Message}", ex);
        }
    }

    public async Task<List<SqlInjectionResult>> GetSqlInjectionResultsAsync(string baseUrl)
    {
        try
        {
            string apiUrl = $"/JSON/alert/view/alerts/?baseurl={Uri.EscapeDataString(baseUrl)}";
            var response = await _httpClient.GetAsync(apiUrl);
            response.EnsureSuccessStatusCode();
            var content = await response.Content.ReadAsStringAsync();
            var alerts = JObject.Parse(content)["alerts"] as JArray;

            var sqlInjectionPluginIds = new HashSet<string>
            {
                "40018", "40019", "40020", "40021", "40022", "40023", "40024", "40025",
                "90018", "90019", "90020"
            };

            var results = new List<SqlInjectionResult>();

            if (alerts != null)
            {
                foreach (var alert in alerts)
                {
                    if (sqlInjectionPluginIds.Contains(alert["pluginId"]?.ToString()))
                    {
                        results.Add(new SqlInjectionResult
                        {
                            Url = alert["url"]?.ToString(),
                            Payload = alert["param"]?.ToString() + "=" + alert["attack"]?.ToString(),
                            Parameter=alert["param"]?.ToString(),
                            InputVector=alert["inputVector"]?.ToString() 
                                          ?? alert["InputVector"]?.ToString() 
                                            ?? alert["Input Vector"]?.ToString(),
                            Evidence = alert["evidence"]?.ToString(),
                            Confidence = alert["confidence"]?.ToString(),
                            Risk = alert["risk"]?.ToString(),
                            Description = alert["description"]?.ToString(),
                            Solution = alert["solution"]?.ToString(),
                        });
                    }
                }
            }

            return results;
        }
        catch (Exception ex)
        {
            throw new Exception($"Failed to fetch SQL Injection scan results for {baseUrl}: {ex.Message}", ex);
        }
    }


    public async Task CancelScanAsync(int scanId)
    {
        try
        {
            var response = await _httpClient.GetAsync($"/JSON/ascan/action/stop/?scanId={scanId}");
            response.EnsureSuccessStatusCode();
        }
        catch (Exception ex)
        {
            throw new Exception($"Failed to cancel scan with ID {scanId}: {ex.Message}", ex);
        }
    }
}