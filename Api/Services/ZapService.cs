using System;
using System.Net.Http;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;

public class ZapService
{
    private readonly HttpClient _httpClient;
    private const string ApiKey = "tku4lsd6a3lth0ku6bgepu637i"; // Replace with your actual ZAP API key

    public ZapService(HttpClient httpClient)
    {
        _httpClient = httpClient;
        _httpClient.BaseAddress = new Uri("http://localhost:8080"); // Set to ZAP's actual base address
        _httpClient.DefaultRequestHeaders.Add("X-ZAP-API-Key", ApiKey); // Include API key in headers
    }

    /// <summary>
    /// Initiates an active scan on the given URL using ZAP's API.
    /// </summary>
    /// <param name="url">The URL to scan.</param>
    /// <returns>The scan ID if successful.</returns>
    public async Task<string> StartScanAsync(string url)
    {
        try
        {
            
            var response = await _httpClient.GetAsync($"/JSON/ascan/action/scan/?url={Uri.EscapeDataString(url)}");
            response.EnsureSuccessStatusCode(); // Throws if response status is not success
            
            var content = await response.Content.ReadAsStringAsync();
            var scanId = JObject.Parse(content)["scan"]?.ToString();

            if (string.IsNullOrEmpty(scanId))
            {
                throw new Exception("Scan ID not found in the response.");
            }

            return scanId;
        }
        catch (HttpRequestException httpRequestException)
        {
            Console.WriteLine($"HTTP Request Error: {httpRequestException.Message}");
            throw new Exception("Error starting ZAP scan: " + httpRequestException.Message);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
            throw new Exception("Error starting ZAP scan: " + ex.Message);
        }
    }

    /// <summary>
    /// Retrieves the status of an ongoing scan by its scan ID.
    /// </summary>
    /// <param name="scanId">The scan ID.</param>
    /// <returns>The scan progress status as a string.</returns>
    public async Task<string> GetScanStatusAsync(string scanId)
    {
        try
        {
            var response = await _httpClient.GetAsync($"/JSON/ascan/view/status/?scanId={scanId}");
            response.EnsureSuccessStatusCode();

            var content = await response.Content.ReadAsStringAsync();
            return JObject.Parse(content)["status"]?.ToString();
        }
        catch (HttpRequestException httpRequestException)
        {
            Console.WriteLine($"HTTP Request Error: {httpRequestException.Message}");
            throw new Exception("Error retrieving scan status: " + httpRequestException.Message);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
            throw new Exception("Error retrieving scan status: " + ex.Message);
        }
    }

    /// <summary>
    /// Retrieves the results of a completed scan.
    /// </summary>
    /// <param name="scanId">The scan ID.</param>
    /// <returns>The scan results as a JSON string.</returns>
    public async Task<string> GetScanResultsAsync(string scanId)
    {
        try
        {
            var response = await _httpClient.GetAsync($"/JSON/core/view/alerts/?baseurl=&scanId={scanId}");
            response.EnsureSuccessStatusCode();

            return await response.Content.ReadAsStringAsync();
        }
        catch (HttpRequestException httpRequestException)
        {
            Console.WriteLine($"HTTP Request Error: {httpRequestException.Message}");
            throw new Exception("Error retrieving scan results: " + httpRequestException.Message);
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error: {ex.Message}");
            throw new Exception("Error retrieving scan results: " + ex.Message);
        }
    }
}