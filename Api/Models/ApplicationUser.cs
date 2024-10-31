using Microsoft.AspNetCore.Identity;
using System.ComponentModel.DataAnnotations;

namespace Api.Models
{
    public class ApplicationUser : IdentityUser
    {
        [Required, MaxLength(50)]
        public string FirstName { get; set; }


        [Required, MaxLength(50)]
        public string LastName { get; set; }

         
        public string? Gender { get; set; }

         public byte[]? Image { get; set; }

        public ICollection<Website> Websites { get; set; } = new List<Website>();
        public ICollection<ScanRequest> ScanRequests { get; set; }
        
    }
}