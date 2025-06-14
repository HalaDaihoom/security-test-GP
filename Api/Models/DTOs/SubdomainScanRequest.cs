using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Api.DTOs
{
    public class SubdomainScanRequest
    {
        public string Subdomain { get; set; } // e.g., vulnerable.example.com
    }

    public class SubdomainScanResult
    {
        public bool IsVulnerable { get; set; }
        public string Summary { get; set; }
        public string Details { get; set; }
    }

}
