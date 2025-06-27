using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Api.DTOs
{
    public class XssScanRequestDto
    {
        public string TargetUrl { get; set; }
    }
}
