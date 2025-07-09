using System;
using System.Threading;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using Api.Models;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Api.DTOs;
using Api.Services;
using Microsoft.Extensions.Configuration;
using System.Net.Http;
using System.Text;
using iTextSharp.text;
using iTextSharp.text.pdf;


namespace Api.Controllers
{

    /// <summary>
    /// Controller for handling user-related operations such as vulnerability scanning and history retrieval.
    /// </summary>

    [Authorize(Roles = "User")]
    [Route("api/")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly IAuthService _authService;
        private readonly ApiContext _context;
        private readonly ZapService _zapService;
        private readonly IWebHostEnvironment _webHostEnvironment;

        private readonly ILogger<UserController> _logger;
        private readonly IHttpClientFactory _httpClientFactory;
        private readonly IConfiguration _configuration;
        public UserController(IAuthService authService, ApiContext context, ZapService zapService, IWebHostEnvironment webHostEnvironment, ILogger<UserController> logger, IHttpClientFactory httpClientFactory, IConfiguration configuration)
        {
            _authService = authService;
            _context = context;
            _zapService = zapService;
            _webHostEnvironment = webHostEnvironment;
            _logger = logger;
            _httpClientFactory = httpClientFactory;
            _configuration = configuration;
        }



        /// <summary>
        /// Initiates an automatic vulnerability scan for a given website URL.
        /// </summary>
        /// <remarks>
        /// **URL**: `POST /api/scanners/automatic-scanner`  
        /// **Purpose**:  
        /// - Initiates an automatic vulnerability scan using ZAP.  
        /// - Associates the scan with the authenticated user.  
        /// - Performs a spider crawl followed by an active vulnerability scan.  
        /// - Saves the scan request and results in the database.  
        ///
        /// **Request Body**:  
        /// A `Website` instance with the following fields:  
        /// - `Url` (string, required): The website URL to scan.  
        ///
        /// **Responses**:  
        /// - `200 OK`: Scan completed successfully with a redirect URL to view the results.  
        /// - `400 Bad Request`: Invalid input or malformed URL.  
        /// - `401 Unauthorized`: User is not authenticated.  
        /// - `500 Internal Server Error`: Error during the scan process.  
        /// </remarks>

        [HttpPost("scan-requests")]
        public async Task<IActionResult> AutomaticScanner([FromBody] Website model, CancellationToken cancellationToken)
        {
            if (model == null || !ModelState.IsValid)
                return BadRequest("Invalid request. Please provide a valid website URL.");

            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userId))
                return Unauthorized("User ID not found.");

            model.UserId = userId;
            model.CreatedAt = DateTime.UtcNow;

            _context.Websites.Add(model);
            await _context.SaveChangesAsync(cancellationToken);

            var scanRequest = new ScanRequest
            {
                UserId = userId,
                WebsiteId = model.WebsiteId,
                Status = "In Progress",
                StartedAt = DateTime.UtcNow
            };

            _context.ScanRequests.Add(scanRequest);
            await _context.SaveChangesAsync(cancellationToken);

            try
            {
                // Start ZAP Spider
                var spiderId = await _zapService.StartSpiderAsync(model.Url, cancellationToken);
                string spiderStatus;
                do
                {
                    await Task.Delay(5000, cancellationToken);
                    spiderStatus = await _zapService.GetSpiderStatusAsync(spiderId, cancellationToken);
                    _logger.LogInformation($"Spider status: {spiderStatus}");
                } while (spiderStatus != "100");

                // Start ZAP Scan
                // Start ZAP Scan
                var scanId = await _zapService.StartScanAsync(model.Url, cancellationToken);

                // ✅ Add this check here
                if (scanId <= 0)
                {
                    _logger.LogError("Invalid scanId returned from ZAP.");
                    return StatusCode(500, "Failed to start scan.");
                }

                scanRequest.ZAPScanId = scanId;
                await _context.SaveChangesAsync(cancellationToken);



                // Wait for scan to complete
                string scanStatus;
                const int maxRetries = 120;
                int retries = 0;
                do
                {
                    await Task.Delay(5000, cancellationToken);
                    scanStatus = await _zapService.GetScanStatusAsync(scanId, cancellationToken);
                    _logger.LogInformation($"Scan status: {scanStatus}");
                    retries++;
                } while (!scanStatus.Equals("100", StringComparison.OrdinalIgnoreCase) &&
                         retries < maxRetries);

                if (retries >= maxRetries)
                {
                    _logger.LogError($"Scan for {scanId} timed out.");
                    return StatusCode(504, "Scan timed out.");
                }

                await Task.Delay(2000, cancellationToken); // short pause
                await _zapService.WaitForAlertsToSettleAsync(model.Url, cancellationToken: cancellationToken);


                scanRequest.Status = "Completed";
                scanRequest.CompletedAt = DateTime.UtcNow;
                await _context.SaveChangesAsync(cancellationToken);
                _logger.LogInformation($"Returning redirectUrl:/scanner/scan-result?scanId={scanId}");

                // return Ok(new
                // {
                //     Message = "Scan completed successfully!",
                //     redirectUrl = $"/scanner/scan-result?scanId={scanId}"
                // });
                return Ok(new
                {
                    Message = "Scan completed successfully!",
                    redirectUrl = $"/scanner/scan-result?requestId={scanRequest.RequestId}"
                });


            }
            catch (Exception ex)
            {
                _logger.LogError($"Error during scan: {ex.Message}");
                return StatusCode(500, "An error occurred during the scan process.");
            }
        }

 [HttpGet("/api/scan-results/by-request/{requestId}")]
public async Task<IActionResult> GetScanResultsByRequest(int requestId, CancellationToken cancellationToken)
{
    try
    {
        var scanRequest = await _context.ScanRequests
            .Include(r => r.Website)
            .FirstOrDefaultAsync(r => r.RequestId == requestId, cancellationToken);

        if (scanRequest == null)
            return NotFound("Scan request not found.");

        if (scanRequest.Website == null)
            return NotFound("Associated website not found for this request.");

        string baseUrl = scanRequest.Website.Url;

        if (string.IsNullOrWhiteSpace(baseUrl))
            return NotFound("Website URL is missing for this scan request.");

        string scanResultsJson = await _zapService.GetScanResultsAsync(baseUrl, cancellationToken);
        _logger.LogInformation("Raw ZAP scan results: {Json}", scanResultsJson);

        if (string.IsNullOrWhiteSpace(scanResultsJson))
        {
            _logger.LogWarning("ZAP returned empty scan results for URL: {Url}", baseUrl);
            return Ok(new { Message = "No vulnerabilities found.", Results = Array.Empty<ScanResult>() });
        }

        var zapAlerts = JsonConvert.DeserializeObject<ZapAlertsDtoResponse>(scanResultsJson);

        if (zapAlerts?.Alerts == null || !zapAlerts.Alerts.Any())
        {
            return Ok(new { Message = "No vulnerabilities found.", Results = Array.Empty<ScanResult>() });
        }

        var resultsToSave = zapAlerts.Alerts.Select(alert => new ScanResult
        {
            RequestId = requestId,
            ZAPScanId = scanRequest.ZAPScanId,
            Severity = alert.Risk,
            Details = JsonConvert.SerializeObject(alert)
        }).ToList();

        var existingResults = await _context.ScanResults
            .Where(r => r.RequestId == requestId)
            .ToListAsync(cancellationToken);

        if (!existingResults.Any())
        {
            await _context.ScanResults.AddRangeAsync(resultsToSave, cancellationToken);
            await _context.SaveChangesAsync(cancellationToken);
        }

        return Ok(new { Message = "Scan results retrieved successfully.", Results = resultsToSave });
    }
    catch (Exception ex)
    {
        _logger.LogError(ex, $"Error retrieving scan results for requestId {requestId}");
        return StatusCode(500, "Failed to retrieve scan results.");
    }
}



        [HttpGet("scan-results")]
        public async Task<IActionResult> GetScanHistory(CancellationToken cancellationToken)
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userId))
                return Unauthorized("User ID not found.");

            var scanHistory = await _context.ScanRequests
                .Include(sr => sr.Website)
                .Include(sr => sr.Vulnerability)
                .Where(sr => sr.UserId == userId)
                .OrderByDescending(sr => sr.StartedAt)
                .Select(sr => new
                {
                    sr.RequestId,
                    sr.Website.Url,
                    sr.StartedAt,
                    sr.ZAPScanId,
                    VulnerabilityType = sr.Vulnerability != null ? sr.Vulnerability.VulnerabilityName : null
                })
                .ToListAsync(cancellationToken);

            return Ok(scanHistory);
        }

        [HttpPost("summarize-scan-results")]
        public async Task<IActionResult> SummarizeScanResults([FromBody] SummarizeScanResults request, CancellationToken cancellationToken)
        {
            try
            {
                _logger.LogInformation($"Processing summary request for RequestId: {request.RequestId}");

                if (request.RequestId <= 0)
                    return BadRequest("Invalid RequestId.");

                var results = await _context.ScanResults
                .Where(r => r.RequestId == request.RequestId)
                .ToListAsync(cancellationToken);


                if (!results.Any())
                    return NotFound("No scan results found for the provided ID.");

                var combinedDetails = string.Join("\n", results.Select(r => $"{r.Severity}: {r.Details}"));
                var summary = await SummarizeWithGemini(combinedDetails, cancellationToken);

                if (string.IsNullOrEmpty(summary))
                {
                    _logger.LogError("Failed to generate summary: Gemini API returned null or empty response.");
                    return StatusCode(500, "Failed to generate summary due to Gemini API response.");
                }

                foreach (var result in results)
                {
                    result.Summary = summary;
                }

                await _context.SaveChangesAsync(cancellationToken);

                return Ok(new
                {
                    Message = "Summary generated and saved successfully",
                    Summary = summary
                });
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error in SummarizeScanResults: {ex.Message}");
                return StatusCode(500, "Failed to generate and save summary");
            }
        }

        private async Task<string> SummarizeWithGemini(string inputText, CancellationToken cancellationToken)
        {
            try
            {
                var apiKey = _configuration["Gemini:ApiKey"];
                if (string.IsNullOrEmpty(apiKey))
                {
                    _logger.LogError("Gemini API key is not configured.");
                    throw new InvalidOperationException("Gemini API key is not configured.");
                }

                var httpClient = _httpClientFactory.CreateClient();
                var prompt = $@"
            As a senior cybersecurity engineer, analyze the provided ZAP scan results and generate a comprehensive website vulnerability scanner report similar to a professional security audit. The report should be detailed, structured, and include the following sections:

            1. **Executive Summary** (2-3 sentences):
            - Provide a high-level overview of the scan results, summarizing the overall risk level and key findings.
            - Highlight the number of vulnerabilities found and their severity (Critical, High, Medium, Low, Info).

            2. **Scan Information**:
            - Include scan metadata such as:
                - Start time (use current UTC time as a placeholder: {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss UTC}).
                - Finish time (assume scan completed 1-2 minutes after start for estimation).
                - Scan duration (calculate based on start and finish times).
                - Tests performed (e.g., 'X/Y tests completed' based on input data or assume full coverage).
                - Scan status (e.g., 'Finished').

            3. **Overall Risk Level**:
            - Assign an overall risk level (Critical, High, Medium, Low) based on the highest severity of vulnerabilities found.
            - Provide a brief justification for the risk level.

            4. **Findings Summary**:
            - Summarize the number of vulnerabilities by severity:
                - Critical (CVSS >= 9.0)
                - High (CVSS 7.0–8.9)
                - Medium (CVSS 4.0–6.9)
                - Low (CVSS 0.1–3.9)
                - Info (CVSS 0.0 or informational issues)
            - Include a brief description of the most significant vulnerabilities.

            5. **Detailed Findings**:
            - For each vulnerability in the scan results, provide:
                - **Title**: Name of the vulnerability (e.g., 'Missing Content-Security-Policy Header').
                - **Port/Protocol**: Specify the affected port (e.g., 443/tcp) if applicable.
                - **URL Evidence**: List the affected URL(s) or endpoints.
                - **Risk Description**: Explain the risk posed by the vulnerability, including potential attack scenarios.
                - **Recommendation**: Provide actionable remediation steps tailored to the vulnerability.
                - **References**: Include 1-2 relevant references (e.g., OWASP, CWE, or other authoritative sources).
                - **Classification**:
                - Map to CWE (Common Weakness Enumeration) if applicable.
                - Map to OWASP Top 10 (2017 and 2021 editions) categories.
                - **Status**: Indicate if the finding is CONFIRMED or UNCONFIRMED.

            6. **Scan Coverage Information**:
            - List the types of tests performed (e.g., checking for missing headers, website technologies, SQL injection, etc.).
            - If specific tests were not performed (e.g., due to scan limitations), note them as 'Not Tested' and suggest a deeper scan.
            - Example tests to include (based on input or assumption):
                - Missing HTTP headers (Content-Security-Policy, Strict-Transport-Security, etc.).
                - Website fingerprinting and technology detection.
                - Checks for sensitive files (e.g., robots.txt, security.txt).
                - SQL injection, XSS, file inclusion, etc. (if applicable).

            7. **Scan Statistics**:
            - Provide metrics such as:
                - Number of unique injection points detected.
                - Number of URLs spidered.
                - Total number of HTTP requests made.
                - Average response time (in milliseconds).

            8. **Recommendations for Further Action**:
            - Suggest next steps, such as running a deeper scan (e.g., for SQL injection, XSS, etc.) if not already performed.
            - Recommend reviewing specific configurations or implementing security best practices.

            9. **False Positives (if any)**:
            - Identify any findings that might be false positives and explain why.
            - Provide guidance on how to verify or dismiss them.

            Scan Results:
            {inputText}

            Format the output as a structured, professional report with clear section headings. Ensure the tone is technical, concise, and suitable for a cybersecurity audience. If specific details (e.g., scan times, test counts) are not provided in the input, make reasonable assumptions based on typical website scans. Include relevant OWASP and CWE classifications for all findings."
                    ;

                var requestBody = new
                {
                    contents = new[]
                    {
                new
                {
                    parts = new[]
                    {
                        new { text = prompt }
                    }
                }
            },
                    generationConfig = new
                    {
                        temperature = 0.3,
                        topP = 0.8,
                        maxOutputTokens = 4096 // Increased to accommodate a more extensive report
                    }
                };

                var jsonRequest = JsonConvert.SerializeObject(requestBody);
                var content = new StringContent(jsonRequest, Encoding.UTF8, "application/json");

                var response = await httpClient.PostAsync(
                    $"https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key={apiKey}",
                    content,
                    cancellationToken);

                var responseString = await response.Content.ReadAsStringAsync(cancellationToken);

                if (!response.IsSuccessStatusCode)
                {
                    _logger.LogError($"Gemini API call failed with status {response.StatusCode}: {responseString}");
                    return null;
                }

                var responseObject = JsonConvert.DeserializeObject<dynamic>(responseString);
                var text = responseObject?.candidates?[0]?.content?.parts?[0]?.text?.ToString();

                if (string.IsNullOrEmpty(text))
                {
                    _logger.LogError("Gemini API response is empty or missing expected text field.");
                    return null;
                }

                return text;
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error calling Gemini API: {ex.Message}, StackTrace: {ex.StackTrace}");
                return null;
            }
        }

        /// <summary>
        /// Retrieves the summary for a given scan ID.
        /// </summary'ın
        [HttpGet("summary")]
        public async Task<IActionResult> GetSummary([FromQuery] int requestId, CancellationToken cancellationToken)
        {
            try
            {
                var scanResult = await _context.ScanResults
                    .Where(r => r.RequestId == requestId && !string.IsNullOrEmpty(r.Summary))
                    .FirstOrDefaultAsync(cancellationToken);

                if (scanResult == null)
                    return NotFound("Summary not available for the provided request ID.");

                return Ok(new { Summary = scanResult.Summary });
            }
            catch (Exception ex)
            {
                _logger.LogError($"Error retrieving summary: {ex.Message}");
                return StatusCode(500, "Failed to retrieve summary.");
            }
        }


    }
}
