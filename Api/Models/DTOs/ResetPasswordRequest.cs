using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Api.Models.DTOs
{
    public class ResetPasswordRequest
    {
        public string Email { get; set; }
        public string ClientURI { get; set; } // e.g. http://localhost:3000/reset-password
    }




    public class ResetPasswordModel
    {
        public string UserId { get; set; }
        public string Token { get; set; }
        public string NewPassword { get; set; }
    }



    public class EmailSettings
    {
        public string Sender { get; set; }
        public string AppPassword { get; set; }
    }
}