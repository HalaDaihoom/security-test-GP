using System.Net.Http;
using System.Text.Json;

public class SubdomainExtractorService
{
    private readonly HttpClient _httpClient;

    public SubdomainExtractorService(HttpClient httpClient)
    {
        _httpClient = httpClient;
    }

    public async Task<List<string>> GetSubdomainsAsync(string domain)
    {
        var result = new List<string>();
        var url = $"https://crt.sh/?q=%25.{domain}&output=json";

        try
        {
            var response = await _httpClient.GetAsync(url);
            response.EnsureSuccessStatusCode();

            var json = await response.Content.ReadAsStringAsync();
            var entries = JsonDocument.Parse(json).RootElement;

            var seen = new HashSet<string>();

            foreach (var entry in entries.EnumerateArray())
            {
                if (entry.TryGetProperty("name_value", out var nameValue))
                {
                    var lines = nameValue.ToString().Split('\n');

                    foreach (var sub in lines)
                    {
                        var subdomain = sub.Trim();
                        if (subdomain.EndsWith(domain) && seen.Add(subdomain))
                        {
                            result.Add(subdomain);
                        }
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Error extracting subdomains: {ex.Message}");
        }

        return result;
    }
}
