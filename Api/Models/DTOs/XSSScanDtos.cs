using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Api.DTOs
{
    public class XSSScanRequestDto
    {
        public string Url { get; set; }
        public bool DeepScan { get; set; } = false;
    }

    public class XSSScanResultDto
    {
        public int ResultId { get; set; }
        public string Severity { get; set; }
        public string Details { get; set; }
        public string Summary { get; set; }
        public string PayloadUsed { get; set; }
        public string VulnerabilityType { get; set; }
        public string VulnerabilityName { get; set; }
    }

    public class XSSScanReportDto
    {
        public string Url { get; set; }
        public DateTime ScanDate { get; set; }
        public int TotalVulnerabilities { get; set; }
        public List<XSSScanResultDto> Results { get; set; }
    }
}