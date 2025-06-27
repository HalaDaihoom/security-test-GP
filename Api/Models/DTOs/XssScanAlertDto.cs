namespace Api.DTOs
{
    public class XssScanAlertDto
    {
        public string XssType { get; set; }
        public string AffectedUrl { get; set; }
        public string Risk { get; set; }
        public string Confidence { get; set; }
        public string Description { get; set; }
        public string Solution { get; set; }
        public string Payload { get; set; }
    }
}