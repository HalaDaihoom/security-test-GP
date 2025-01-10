namespace Api.DTOs
{
    public class ZapAlertsDtoResponse
    {
        public List<ZapAlert> Alerts { get; set; }
    }

    public class ZapAlert
    {
        public string Alert { get; set; } // The type of vulnerability, e.g., "SQL Injection"
        public string URL { get; set; }  // The affected URL
        public string Risk { get; set; } // The severity: High, Medium, Low
        public string Confidence { get; set; } // The confidence level
        public string Description { get; set; } // A brief description of the vulnerability
        // Add more fields as needed based on ZAP's response
    }
}
