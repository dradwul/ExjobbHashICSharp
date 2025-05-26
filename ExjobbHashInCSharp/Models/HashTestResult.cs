namespace ExjobbHashInCSharp.Models;

public class HashTestResult
{
	public string Algorithm { get; set; } = string.Empty;
	public int InputSize { get; set; }
	public int Iterations { get; set; }
	public double TotalTimeMs { get; set; }
	public double TimePerHashMicroseconds { get; set; }
	public double ThroughputMBps { get; set; }
}