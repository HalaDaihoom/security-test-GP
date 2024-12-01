using System;
using System.Net.Http;
using System.Text;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;
using Newtonsoft.Json;


public class ZapService
{
    private readonly HttpClient _httpClient;
    private const string ApiKey = "tku4lsd6a3lth0ku6bgepu637i"; 

    public ZapService(HttpClient httpClient)
    {
        _httpClient = httpClient;
        _httpClient.BaseAddress = new Uri("http://localhost:8080"); 
        _httpClient.DefaultRequestHeaders.Add("X-ZAP-API-Key", ApiKey); 
    }

    
    public async Task<string> StartScanAsync(string url)
    {
        try
        {
            //var response = await _httpClient.GetAsync($"/JSON/ascan/action/scan/?url={Uri.EscapeDataString(url)}&apikey={ApiKey}");

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