using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Api.DTOs
{
    public class SubdomainSourceDto
    {
        public string Subdomain { get; set; }
        public bool Resolves { get; set; } 
        public string IpAddress { get; set; }
        public string Source { get; set; }

    }

}