using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using Api.Models;
using Microsoft.Extensions.Logging;
using Api.Services;
using System.Net.Http;
using Api.Services.Scanners;
using Api.DTOs;
using System.Collections.Generic;
using iTextSharp.text;
using iTextSharp.text.pdf;
using System.IO;
using System.Linq;

namespace Api.Controllers
{
    [Authorize(Roles = "User")]
    [Route("api/")]
    [ApiController]
    public class SubdomainFinderController : ControllerBase
    {
        private readonly SubdomainTakeoverScanner _scanner;
        private readonly SubdomainExtractorService _extractor;
        private readonly ApiContext _context;
        private readonly ILogger<SubdomainFinderController> _logger;
        private readonly IHttpClientFactory _clientFactory;
        private static List<SubdomainCheckResult> _lastScanResults = new();

        public SubdomainFinderController(
            SubdomainTakeoverScanner scanner,
            SubdomainExtractorService extractor,
            ApiContext context,
            ILogger<SubdomainFinderController> logger,
            IHttpClientFactory clientFactory)
        {
            _scanner = scanner;
            _extractor = extractor;
            _context = context;
            _logger = logger;
            _clientFactory = clientFactory;
        }

        public class DomainInput
        {
            public string Domain { get; set; }
        }

        [HttpPost("subdomains")]
        public async Task<IActionResult> GetSubdomainsWithSources([FromBody] DomainInput input)
        {
            var domain = input?.Domain;
            if (string.IsNullOrWhiteSpace(domain))
                return BadRequest("Domain is required.");

            var results = await _extractor.GetSubdomainsWithSourcesAsync(domain);

            return Ok(new
            {
                domain,
                total = results.Count,
                subdomains = results
            });
        }

        [HttpGet("subdomain-reports/{domain}")]
        public async Task<IActionResult> GetSubdomainReport(string domain)
        {
            if (string.IsNullOrWhiteSpace(domain))
                return BadRequest("Domain is required.");

            domain = domain.Trim();

            var subdomainDtos = await _extractor.GetSubdomainsWithSourcesAsync(domain);
            if (subdomainDtos.Count == 0)
                return NotFound("No subdomains found.");

            var results = subdomainDtos.Select(r => new SubdomainSourceDto
            {
                Subdomain = r.Subdomain,
                Resolves = r.Resolves,
                IpAddress = r.IpAddress,
                Source = r.Source
            }).ToList();

            int total = results.Count;
            int resolvesCount = results.Count(r => r.Resolves);

            using var memoryStream = new MemoryStream();
            Document document = new Document(PageSize.A4, 40, 40, 60, 40);
            PdfWriter.GetInstance(document, memoryStream);
            document.Open();

            Font titleFont = FontFactory.GetFont(FontFactory.HELVETICA_BOLD, 18);
            Font subtitleFont = FontFactory.GetFont(FontFactory.HELVETICA, 12);
            Font headerFont = FontFactory.GetFont(FontFactory.HELVETICA_BOLD, 10);
            Font cellFont = FontFactory.GetFont(FontFactory.HELVETICA, 9);

            // Header
            document.Add(new Paragraph("BugSloth - Subdomain Enumeration Report", titleFont) { Alignment = Element.ALIGN_CENTER });
            document.Add(new Paragraph($"Target Domain: {domain}", subtitleFont));
            document.Add(new Paragraph($"Generated on: {DateTime.UtcNow:yyyy-MM-dd HH:mm} UTC", subtitleFont));
            document.Add(Chunk.NEWLINE);

            // Summary section
            document.Add(new Paragraph("Summary", headerFont));
            document.Add(new Paragraph($"Total Subdomains Found: {total}", cellFont));
            document.Add(new Paragraph($"Resolvable Subdomains: {resolvesCount}", cellFont));
            document.Add(Chunk.NEWLINE);

            // Table
            PdfPTable table = new PdfPTable(4) { WidthPercentage = 100 };
            table.SetWidths(new float[] { 3, 1.2f, 3, 2 });

            table.AddCell(new PdfPCell(new Phrase("Subdomain", headerFont)));
            table.AddCell(new PdfPCell(new Phrase("Resolves", headerFont)));
            table.AddCell(new PdfPCell(new Phrase("IP Address", headerFont)));
            table.AddCell(new PdfPCell(new Phrase("Source", headerFont)));

            foreach (var result in results)
            {
                table.AddCell(new PdfPCell(new Phrase(result.Subdomain ?? "N/A", cellFont)));
                table.AddCell(new PdfPCell(new Phrase(result.Resolves ? "Yes" : "No", cellFont)));
                table.AddCell(new PdfPCell(new Phrase(result.IpAddress ?? "N/A", cellFont)));
                table.AddCell(new PdfPCell(new Phrase(result.Source ?? "N/A", cellFont)));
            }

            document.Add(table);
            document.Close();

            var safeDomain = string.Join("_", domain.Split(Path.GetInvalidFileNameChars()));
            return File(memoryStream.ToArray(), "application/pdf", $"subdomain-report-{safeDomain}.pdf");
        }
    }
}


// using System;
// using System.Threading.Tasks;
// using Microsoft.AspNetCore.Authorization;
// using Microsoft.AspNetCore.Mvc;
// using Microsoft.EntityFrameworkCore;
// using System.Security.Claims;
// using Api.Models;
// using Microsoft.Extensions.Logging;
// using Api.Services;
// using System.Net.Http;
// using Api.Services.Scanners;
// using Api.DTOs;
// using System.Collections.Generic;
// using iTextSharp.text;
// using iTextSharp.text.pdf;

// namespace Api.Controllers
// {
//     [Authorize(Roles = "User")]
//     [Route("api/")]
//     [ApiController]
//     public class SubdomainFinderController : ControllerBase
//     {
//         private readonly SubdomainTakeoverScanner _scanner;
//         private readonly SubdomainExtractorService _extractor;
//         private readonly ApiContext _context;
//         private readonly ILogger<SubdomainFinderController> _logger;
//         private readonly IHttpClientFactory _clientFactory;
//         private static List<SubdomainCheckResult> _lastScanResults = new();

//         public SubdomainFinderController(
//             SubdomainTakeoverScanner scanner,
//             SubdomainExtractorService extractor,
//             ApiContext context,
//             ILogger<SubdomainFinderController> logger,
//             IHttpClientFactory clientFactory)
//         {
//             _scanner = scanner;
//             _extractor = extractor;
//             _context = context;
//             _logger = logger;
//             _clientFactory = clientFactory;
//         }




//         public class DomainInput
//         {
//             public string Domain { get; set; }
//         }
//         [HttpPost("subdomains")]
//         public async Task<IActionResult> GetSubdomainsWithSources([FromBody] DomainInput input)
//         {
//             var domain = input?.Domain;
//             if (string.IsNullOrWhiteSpace(domain))
//                 return BadRequest("Domain is required.");

//             var results = await _extractor.GetSubdomainsWithSourcesAsync(domain);

//             return Ok(new
//             {
//                 domain,
//                 total = results.Count,
//                 subdomains = results
//             });
//         }

//         [HttpGet("subdomain-reports/{domain}")]
//         public async Task<IActionResult> GetSubdomainReport(string domain)
//         {
//             if (string.IsNullOrWhiteSpace(domain))
//                 return BadRequest("Domain is required.");

//             domain = domain.Trim();

//             var subdomainDtos = await _extractor.GetSubdomainsWithSourcesAsync(domain);
//             if (subdomainDtos.Count == 0)
//                 return NotFound("No subdomains found.");

//             var results = subdomainDtos.Select(r => new SubdomainSourceDto
//             {
//                 Subdomain = r.Subdomain,
//                 Resolves = r.Resolves,
//                 IpAddress = r.IpAddress,
//                 Source = r.Source
//             }).ToList();

//             using var memoryStream = new MemoryStream();
//             Document document = new Document(PageSize.A4, 40, 40, 60, 40);
//             PdfWriter.GetInstance(document, memoryStream);
//             document.Open();

//             Font titleFont = FontFactory.GetFont(FontFactory.HELVETICA_BOLD, 16);
//             Font headerFont = FontFactory.GetFont(FontFactory.HELVETICA_BOLD, 10);
//             Font cellFont = FontFactory.GetFont(FontFactory.HELVETICA, 9);

//             document.Add(new Paragraph($"Subdomain Report for {domain}", titleFont));
//             document.Add(new Paragraph($"Generated on: {DateTime.UtcNow:yyyy-MM-dd HH:mm} UTC\n\n", cellFont));

//             PdfPTable table = new PdfPTable(4) { WidthPercentage = 100 };
//             table.SetWidths(new float[] { 3, 1.2f, 3, 2 });

//             table.AddCell(new PdfPCell(new Phrase("Subdomain", headerFont)));
//             table.AddCell(new PdfPCell(new Phrase("Resolves", headerFont)));
//             table.AddCell(new PdfPCell(new Phrase("IP Address", headerFont)));
//             table.AddCell(new PdfPCell(new Phrase("Source", headerFont)));

//             foreach (var result in results)
//             {
//                 table.AddCell(new PdfPCell(new Phrase(result.Subdomain ?? "N/A", cellFont)));
//                 table.AddCell(new PdfPCell(new Phrase(result.Resolves ? "Yes" : "No", cellFont)));
//                 table.AddCell(new PdfPCell(new Phrase(result.IpAddress ?? "N/A", cellFont)));
//                 table.AddCell(new PdfPCell(new Phrase(result.Source ?? "N/A", cellFont)));
//             }

//             document.Add(table);
//             document.Close();

//             var safeDomain = string.Join("_", domain.Split(Path.GetInvalidFileNameChars()));
//             return File(memoryStream.ToArray(), "application/pdf", $"subdomain-report-{safeDomain}.pdf");
//         }

//     }

//     }