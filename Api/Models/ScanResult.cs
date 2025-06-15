using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Api.Models
{
    public class ScanResult
    {
        [Key]
        public int ResultId { get; set; }

        [ForeignKey("ScanRequest")]
        public int RequestId { get; set; }

        public int? ZAPScanId { get; set; }

        [ForeignKey("Vulnerability")]
        public int? VulnerabilityId { get; set; }
        public string? Severity { get; set; }

        public string? Details { get; set; }
        public string? Summary { get; set; } // New property for AI-generated summary

        public string? PayloadUsed { get; set; } // New field
        public string? VulnerabilityType { get; set; } // New field

        public ScanRequest? ScanRequest { get; set; }
        public Vulnerability? Vulnerability { get; set; } 
     

    }
    
}