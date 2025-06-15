using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Api.DTOs
{

    public class DomainScanDto
    {
        public int ResultId { get; set; }
        public string? Subdomain { get; set; } // ✅ فقط في DTO
        public string? Severity { get; set; }
        public string? Summary { get; set; }
        public string? Details { get; set; }
        public string? VulnerabilityType { get; set; }
    }
}