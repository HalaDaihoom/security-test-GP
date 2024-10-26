using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Api.Models
{
    public class Website
    {
        public int WebsiteId { get; set; } 
        [ForeignKey("User")]
        public string UserId { get; set; } 

        [Required]
        [MaxLength(255)]
        public string Url { get; set; } 

        [Required]
        public DateTime CreatedAt { get; set; } 

        
        public ApplicationUser User { get; set; }
       public ICollection<ScanRequest> ScanRequests { get; set; }
    }
}
