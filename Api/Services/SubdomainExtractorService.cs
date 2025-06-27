using System.Net.Http;
using System.Text.Json;
using Api.DTOs;
using Microsoft.Extensions.Configuration;
using System.Net;
using DnsClient;

public class SubdomainExtractorService
{
    private readonly HttpClient _httpClient;
    private readonly string _virustotalApiKey;
    private readonly LookupClient _dnsClient = new();

    public SubdomainExtractorService(HttpClient httpClient, IConfiguration config)
    {
        _httpClient = httpClient;
        _virustotalApiKey = config["VirusTotal:ApiKey"];
    }

    public async Task<List<SubdomainSourceDto>> GetSubdomainsAsync(string domain)
    {
        var results = new List<SubdomainSourceDto>();

        results.AddRange(await GetFromCrtSh(domain));
        results.AddRange(await GetFromVirusTotal(domain));
        results.AddRange(await GetFromAlienVaultAsync(domain));

        var uniqueSubdomains = results
            .GroupBy(r => r.Subdomain.ToLowerInvariant())
            .Select(g => g.First())
            .ToList();

        foreach (var sub in uniqueSubdomains)
        {
            var (resolves, ip) = await GetResolutionInfoAsync(sub.Subdomain);
            sub.Resolves = resolves;
            sub.IpAddress = ip;
        }


        return uniqueSubdomains;
    }

    private async Task<List<SubdomainSourceDto>> GetFromCrtSh(string domain)
    {
        var list = new List<SubdomainSourceDto>();
        try
        {
            var url = $"https://crt.sh/?q=%25.{domain}&output=json";
            var response = await _httpClient.GetAsync(url);
            var json = await response.Content.ReadAsStringAsync();
            var root = JsonDocument.Parse(json).RootElement;

            foreach (var entry in root.EnumerateArray())
            {
                if (entry.TryGetProperty("name_value", out var nameValue))
                {
                    var lines = nameValue.ToString().Split('\n');
                    foreach (var sub in lines)
                    {
                        if (sub.EndsWith(domain))
                            list.Add(new SubdomainSourceDto { Subdomain = sub.Trim(), Source = "crt.sh" });
                    }
                }
            }
        }
        catch { }

        return list;
    }

    private async Task<List<SubdomainSourceDto>> GetFromVirusTotal(string domain)
    {
        var list = new List<SubdomainSourceDto>();
        try
        {
            var request = new HttpRequestMessage(HttpMethod.Get, $"https://www.virustotal.com/api/v3/domains/{domain}/subdomains");
            request.Headers.Add("x-apikey", _virustotalApiKey);

            var response = await _httpClient.SendAsync(request);
            var json = await response.Content.ReadAsStringAsync();
            var root = JsonDocument.Parse(json).RootElement;

            if (root.TryGetProperty("data", out var data))
            {
                foreach (var item in data.EnumerateArray())
                {
                    var subdomain = item.GetProperty("id").GetString();
                    if (subdomain != null)
                        list.Add(new SubdomainSourceDto { Subdomain = subdomain, Source = "VirusTotal" });
                }
            }
        }
        catch { }

        return list;
    }
    private async Task<List<SubdomainSourceDto>> GetFromAlienVaultAsync(string domain)
    {
        var list = new List<SubdomainSourceDto>();
        try
        {
            var url = $"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns";
            var response = await _httpClient.GetAsync(url);
            response.EnsureSuccessStatusCode();

            var json = await response.Content.ReadAsStringAsync();
            var root = JsonDocument.Parse(json).RootElement;

            if (root.TryGetProperty("passive_dns", out var entries))
            {
                foreach (var entry in entries.EnumerateArray())
                {
                    if (entry.TryGetProperty("hostname", out var hostname))
                    {
                        var subdomain = hostname.GetString();
                        if (!string.IsNullOrWhiteSpace(subdomain) && subdomain.EndsWith(domain))
                        {
                            list.Add(new SubdomainSourceDto
                            {
                                Subdomain = subdomain.Trim(),
                                Source = "AlienVault"
                            });
                        }
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Console.WriteLine($"AlienVault error: {ex.Message}");
        }

        return list;
    }


    private async Task<bool> SubdomainResolvesAsync(string subdomain)
    {
        try
        {
            var addresses = await Dns.GetHostAddressesAsync(subdomain);
            return addresses.Length > 0;
        }
        catch
        {
            return false;
        }
    }

    private async Task<(bool resolves, string ip)> GetResolutionInfoAsync(string subdomain)
    {
        try
        {
            var addresses = await Dns.GetHostAddressesAsync(subdomain);
            if (addresses.Length > 0)
            {
                return (true, addresses[0].ToString());
            }
        }
        catch
        {
            // ignored
        }

        return (false, null);
    }


    private async Task<(bool resolves, string ipAddress)> CheckDnsAsync(string subdomain)
    {
        try
        {
            var result = await _dnsClient.QueryAsync(subdomain, QueryType.A);
            var ip = result.Answers.ARecords().FirstOrDefault()?.Address?.ToString();
            return (!string.IsNullOrEmpty(ip), ip ?? "N/A");
        }
        catch
        {
            return (false, "N/A");
        }
    }


    public async Task<List<SubdomainSourceDto>> GetSubdomainsWithSourcesAsync(string domain)
    {

        //return await GetSubdomainsAsync(domain);
     
        var results = new List<SubdomainSourceDto>();

        results.AddRange(await GetFromCrtSh(domain));
        results.AddRange(await GetFromVirusTotal(domain));
        results.AddRange(await GetFromAlienVaultAsync(domain));

        // حذف المكرر
        var uniqueSubdomains = results
            .GroupBy(r => r.Subdomain.ToLowerInvariant())
            .Select(g => g.First())
            .ToList();

        foreach (var sub in uniqueSubdomains)
        {
            var (resolves, ip) = await CheckDnsAsync(sub.Subdomain);
            sub.Resolves = resolves;
            sub.IpAddress = ip;
        }

        return uniqueSubdomains;
    


}

}
