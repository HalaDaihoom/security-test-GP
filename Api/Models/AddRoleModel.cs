using System.ComponentModel.DataAnnotations;

namespace Api.Models
{
    public class AddRoleModel
    {
        [Required]
        public required string UserId { get; set; }

        [Required]
        public required string Role { get; set; }
    }
}