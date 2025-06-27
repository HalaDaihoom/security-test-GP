using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Api.Models.DTOs
{
    public class SqlInjectionResult
    {
           public string Url { get; set; }
    public string Payload { get; set; }
    public string Parameter { get; set; }
    public string InputVector { get; set; }
    public string Evidence { get; set; }
    public string Confidence { get; set; }
    public string Risk { get; set; }
    public string Description { get; set; }
    public string Solution { get; set; }
    }




    public class UrlRequest
    {
        public string Url { get; set; }
    }
}