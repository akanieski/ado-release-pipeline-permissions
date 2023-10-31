public record ResultRow
{
    public required string AssetPath { get; set; }
    public required string Email { get; set; }
    public required string DisplayName { get; set; }
}
public class IdentityData
{
    public List<Identity> Identities { get; set; }
    public bool HasMore { get; set; }
    public int TotalIdentityCount { get; set; }
}

public class Identity
{
    public string IdentityType { get; set; }
    public string FriendlyDisplayName { get; set; }
    public string DisplayName { get; set; }
    public string SubHeader { get; set; }
    public string TeamFoundationId { get; set; }
    public string EntityId { get; set; }
    public List<string> Errors { get; set; }
    public List<string> Warnings { get; set; }
    public string Domain { get; set; }
    public string AccountName { get; set; }
    public bool IsWindowsUser { get; set; }
    public string MailAddress { get; set; }
}