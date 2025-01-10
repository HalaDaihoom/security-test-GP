using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Api.Models
{
    public class ScanRequest
    {
   [Key]
    public int RequestId { get; set; } 

    [ForeignKey("User")]
    public string UserId { get; set; } 
    [ForeignKey("Website")]
    public int WebsiteId { get; set; } 
    
    public int? ZAPScanId { get; set; } // To track ZAP scans

    public string Status { get; set; } 

    public DateTime StartedAt { get; set; } 

    public DateTime? CompletedAt { get; set; } 

    [ForeignKey("Vulnerability")]
    public int? VulnerabilityId { get; set; } 
    public Vulnerability? Vulnerability { get; set; } 

    
    public ICollection<ScanResult>? ScanResults { get; set; }

     public ApplicationUser? User { get; set; }

     public Website? Website { get; set; } 
    }
}