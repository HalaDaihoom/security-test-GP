using System;
using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace Api.DTOs
{
    public class SummarizeScanResults
    {
         public int ScanId { get; set; }
         public int Summary {get;set;}

    }
    
}