using System;
using System.Collections.Concurrent;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Newtonsoft.Json.Linq;
using Microsoft.Extensions.Logging;
using Api.DTOs;
using Api.Models;
using Microsoft.Extensions.Configuration;


namespace Api.Services
{
    public class XssZapService
    {
        private readonly HttpClient _httpClient;
        private readonly ILogger<XssZapService> _logger;
        private static readonly ConcurrentDictionary<string, string> ScanToUrlMap = new();
        private readonly string _apiKey;

        public XssZapService(HttpClient httpClient, ILogger<XssZapService> logger, IConfiguration configuration)
        {
            _httpClient = httpClient;
            _logger = logger;
            _httpClient.BaseAddress = new Uri(configuration["Zap:BaseUrl"]);
            _apiKey = configuration["Zap:ApiKey"];
            _httpClient.DefaultRequestHeaders.Add("X-ZAP-API-Key", _apiKey);
            _httpClient.Timeout = TimeSpan.FromMinutes(120);
        }

        public async Task<string> StartSpiderAsync(string url, CancellationToken cancellationToken = default)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(url) || !Uri.TryCreate(url, UriKind.Absolute, out _))
                    throw new ArgumentException("Invalid target URL.");

                await ConfigureSpiderAsync(cancellationToken);
                var response = await _httpClient.GetAsync($"/JSON/spider/action/scan/?url={Uri.EscapeDataString(url)}&maxChildren=100&recurse=true&subtreeOnly=false", cancellationToken);
                response.EnsureSuccessStatusCode();
                var content = await response.Content.ReadAsStringAsync();
                var spiderId = JObject.Parse(content)["scan"]?.ToString();
                if (string.IsNullOrEmpty(spiderId))
                    throw new Exception($"Spider scan failed. Response: {content}");
                _logger.LogInformation($"Started spider with ID {spiderId} for URL {url}");
                return spiderId;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to start spider for URL {url}: {ex.Message}");
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
                var status = JObject.Parse(content)["status"]?.ToString();
                _logger.LogInformation($"Spider ID {spiderId} status: {status}");
                return status;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to get spider status for ID {spiderId}: {ex.Message}");
                throw new Exception($"Failed to get spider status for ID {spiderId}: {ex.Message}", ex);
            }
        }

        public async Task<int> StartScanAsync(string url, CancellationToken cancellationToken = default)
        {
            try
            {
                if (string.IsNullOrWhiteSpace(url) || !Uri.TryCreate(url, UriKind.Absolute, out _))
                    throw new ArgumentException("Invalid target URL.");

                var scannerIds = "40012,40014,40016,40017"; // Reflected XSS, Stored XSS, Stored XSS Prime, Stored XSS Spider
                await DisableAllScannersAsync(url, cancellationToken);
                await EnableScannersAsync(scannerIds, url, cancellationToken);
                await SetScannerStrengthAsync(scannerIds, "MEDIUM", cancellationToken);

                var response = await _httpClient.GetAsync($"/JSON/ascan/action/scan/?url={Uri.EscapeDataString(url)}&recurse=true", cancellationToken);
                response.EnsureSuccessStatusCode();
                var content = await response.Content.ReadAsStringAsync();
                var scanId = JObject.Parse(content)["scan"]?.ToString();
                if (string.IsNullOrEmpty(scanId))
                    throw new Exception($"Active scan failed. Response: {content}");
                if (!int.TryParse(scanId, out int zapScanId))
                    throw new Exception($"Invalid Scan ID returned: {scanId}");

                ScanToUrlMap[scanId.ToString()] = url;
                _logger.LogInformation($"Started scan with ID {zapScanId} for URL {url}");

                // Background task to monitor scan status
                _ = Task.Run(async () =>
                {
                    while (true)
                    {
                        var statusResponse = await _httpClient.GetAsync($"/JSON/ascan/view/status/?scanId={zapScanId}", cancellationToken);
                        statusResponse.EnsureSuccessStatusCode();
                        var statusJson = await statusResponse.Content.ReadAsStringAsync();
                        var status = JObject.Parse(statusJson)["status"]?.ToString();
                        _logger.LogInformation($"Scan {zapScanId} status: {status}%");
                        if (status == "100") break;
                        await Task.Delay(2000, cancellationToken);
                    }
                }, cancellationToken);

                return zapScanId;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to start scan for URL {url}: {ex.Message}");
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
                var status = JObject.Parse(content)["status"]?.ToString();
                _logger.LogInformation($"Scan ID {scanId} status: {status}");
                return status;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to get scan status for scanId {scanId}: {ex.Message}");
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
                var content = await response.Content.ReadAsStringAsync();
                _logger.LogDebug($"Raw ZAP scan results for {baseUrl}: {content}");
                return content;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to fetch scan results for baseUrl {baseUrl}: {ex.Message}");
                throw new Exception($"Failed to fetch scan results for baseUrl {baseUrl}: {ex.Message}", ex);
            }
        }

        public async Task<List<XssScanAlertDto>> GetProcessedScanResultsAsync(int scanId, CancellationToken cancellationToken)
        {
            try
            {
                if (!ScanToUrlMap.TryGetValue(scanId.ToString(), out var baseUrl))
                    throw new KeyNotFoundException($"Scan ID {scanId} not found in mapping.");

                var json = await GetScanResultsAsync(baseUrl, cancellationToken);
                var alerts = JObject.Parse(json)["alerts"] as JArray;
                var result = new List<XssScanAlertDto>();

                if (alerts == null || !alerts.Any())
                {
                    _logger.LogWarning($"No alerts found for scan ID {scanId} on {baseUrl}");
                    return result;
                }

                foreach (var alert in alerts)
                {
                    var scannerId = alert["pluginId"]?.ToString();
                    var name = alert["alert"]?.ToString()?.ToLower();

                    if (scannerId == "40012" || scannerId == "40014" || scannerId == "40016" || scannerId == "40017")
                    {
                        string xssType = scannerId switch
                        {
                            "40012" => VulnerabilityTypes.ReflectedXSS,
                            "40014" or "40016" or "40017" => VulnerabilityTypes.StoredXSS,
                            _ => "Unknown XSS"
                        };

                        var attack = alert["attack"]?.ToString();
                        var param = alert["param"]?.ToString();
                        var evidence = alert["evidence"]?.ToString();
                        var payload = attack ?? evidence ?? param ?? "No payload available";

                        result.Add(new XssScanAlertDto
                        {
                            XssType = xssType,
                            AffectedUrl = alert["url"]?.ToString(),
                            Risk = alert["risk"]?.ToString(),
                            Confidence = alert["confidence"]?.ToString(),
                            Description = alert["description"]?.ToString(),
                            Solution = alert["solution"]?.ToString(),
                            Payload = payload
                        });
                    }
                }

                _logger.LogInformation($"Processed {result.Count} XSS alerts for scan ID {scanId}");
                return result;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Failed to process scan results for scanId {scanId}: {ex.Message}");
                throw;
            }
        }

        private async Task ConfigureSpiderAsync(CancellationToken cancellationToken)
        {
            var response = await _httpClient.GetAsync($"/JSON/spider/action/setOptionMaxDepth/?Integer=10", cancellationToken);
            response.EnsureSuccessStatusCode();
            response = await _httpClient.GetAsync($"/JSON/spider/action/setOptionProcessForm/?Boolean=true", cancellationToken);
            response.EnsureSuccessStatusCode();
            _logger.LogInformation("Configured spider with max depth 10 and form processing enabled");
        }

        private async Task DisableAllScannersAsync(string url, CancellationToken cancellationToken)
        {
            var response = await _httpClient.GetAsync("/JSON/ascan/action/disableAllScanners/", cancellationToken);
            response.EnsureSuccessStatusCode();
            _logger.LogInformation($"Disabled all scanners for URL {url}");
        }

        private async Task EnableScannersAsync(string scannerIds, string url, CancellationToken cancellationToken)
        {
            var response = await _httpClient.GetAsync($"/JSON/ascan/action/enableScanners/?ids={scannerIds}", cancellationToken);
            response.EnsureSuccessStatusCode();
            _logger.LogInformation($"Enabled scanners {scannerIds} for URL {url}");
        }

        private async Task SetScannerStrengthAsync(string scannerIds, string strength, CancellationToken cancellationToken)
        {
            foreach (var scannerId in scannerIds.Split(','))
            {
                var response = await _httpClient.GetAsync($"/JSON/ascan/action/setScannerAttackStrength/?id={scannerId}&attackStrength={strength}", cancellationToken);
                response.EnsureSuccessStatusCode();
                _logger.LogInformation($"Set attack strength to {strength} for scanner {scannerId}");
            }
        }
    }
}