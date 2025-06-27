using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Api.DTOs
{
    public class CachedSubdomainDto
    {
        public string Subdomain { get; set; }
        public int HttpStatus { get; set; }
        public string Error { get; set; }
        public bool IsVulnerable { get; set; }
        public int ScanRequestId { get; set; }
    }
}
