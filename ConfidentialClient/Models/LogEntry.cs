namespace ConfidentialClient.Models;

// A block can describe either an outbound request (Method/Url) or an inbound response
// (Status/StatusText), each carrying its own headers and body.
public class LogBlock
{
    public string? Method { get; set; }
    public string? Url { get; set; }
    public int? Status { get; set; }
    public string? StatusText { get; set; }
    public Dictionary<string, string>? Headers { get; set; }
    public string? Body { get; set; }
}

public class LogEntry
{
    public string Title { get; set; } = "";
    public string Time { get; set; } = "";
    public LogBlock? Request { get; set; }
    public LogBlock? Response { get; set; }
}
