namespace Api.Models.DTOs
{
    public class InputPoint
    {
        public string Url { get; set; } = string.Empty;
        public string Type { get; set; } = string.Empty; // GET, POST, etc.
        public Dictionary<string, string> Parameters { get; set; } = new Dictionary<string, string>();
        public string FormName { get; set; } = string.Empty;
        public string FormId { get; set; } = string.Empty;
        public string FormAction { get; set; } = string.Empty;
    }

    public class SResult
    {
        public string Url { get; set; } = string.Empty;
        public bool IsVulnerable { get; set; }
        public string Details { get; set; } = string.Empty;
        public string PayloadUsed { get; set; } = string.Empty;
        public string InputPointType { get; set; } = string.Empty;
        public List<string> VulnerableParameters { get; set; } = new List<string>();
        public string? FormName { get; set; }  // Nullable
        public string? FormId { get; set; }    // Nullable
        public string? FormAction { get; set; } // Nullable
        public int ResultId { get; set; }      // Added from ScanResult
        public string? Severity { get; set; }   // Added from ScanResult
        public string? Summary { get; set; }
    }


    public class SRequest
    {
        public string Url { get; set; }
        public bool DeepScan { get; set; } = false;
    }


    public class SqlScanResultDto
    {
        public string? VulnerabilityType  { get; set; }
        public string? Severity { get; set; }
        public string Url { get; set; } = string.Empty;

        public string? Details { get; set; }
        public string? Summary { get; set; }
        public string? PayloadUsed { get; set; } // ← Add this
    }


}

