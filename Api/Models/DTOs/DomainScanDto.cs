using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Api.DTOs
{
    public class DomainRequest
    {
        public string Domain { get; set; } = string.Empty;
    }

    public class DomainScanDto
    {
        public int ResultId { get; set; }
        public string? Subdomain { get; set; }
        public string? Severity { get; set; }
        public string? Summary { get; set; }
        public string? Details { get; set; }
        public string? VulnerabilityType { get; set; }
        public bool IsVulnerable { get; set; }
    }

    public class APIDomainScanDto
    {
        public string Subdomain { get; set; } = string.Empty;
        public int HttpStatus { get; set; }
        public string? Error { get; set; }
        public bool IsVulnerable { get; set; }
        
    }
}
