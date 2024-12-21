using System.ComponentModel.DataAnnotations;

namespace Api.Models
{

public class ZapAlert
{
    public string Alert { get; set; }
    public string Risk { get; set; }
    public string Url { get; set; }
    public string Param { get; set; }
    public string Evidence { get; set; }
    public string Solution { get; set; }
}

public class ZapAlertsResponse
{
    public List<ZapAlert> Alerts { get; set; }
}

}