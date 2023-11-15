using Microsoft.VisualStudio.Services.WebApi;
using Microsoft.TeamFoundation.Core.WebApi;
using Microsoft.VisualStudio.Services.Common;
using Microsoft.VisualStudio.Services.Security.Client;
using Microsoft.VisualStudio.Services.Identity.Client;
using Microsoft.VisualStudio.Services.ReleaseManagement.WebApi.Clients;
using Microsoft.VisualStudio.Services.Graph.Client;
using Microsoft.VisualStudio.Services.Identity;
using System.Globalization;

try
{
    var guid = Guid.Parse(args.GetParameter("--security-namespace", "c788c23e-1b46-4162-8f5e-d7585343b5de", false));
    var orgUrl = args.GetParameter("--org");
    var token = args.GetParameter("--auth");
    var outpath = args.GetParameter("--out");
    Environment.SetEnvironmentVariable("VERBOSE", args.GetParameter("--verbose", "0", false).AsBoolean().ToString());
    var projectName = args.GetParameter("--project");

    var path = args.GetParameter("--releases-path", defaultValue: "", throwOnNull: false);

    using var writer = new StreamWriter(outpath);
    using var csv = new CsvHelper.CsvWriter(writer, CultureInfo.InvariantCulture);

    VssConnection connection = new VssConnection(new Uri(orgUrl),
        new VssBasicCredential(string.Empty, token));
    await connection.ConnectAsync();
    Console.WriteLine("Connection established successfully!");

    var Projects = await connection.GetClientAsync<ProjectHttpClient>();
    var Identity = await connection.GetClientAsync<IdentityHttpClient>();
    var Security = await connection.GetClientAsync<SecurityHttpClient>();
    var Graph = await connection.GetClientAsync<GraphHttpClient>();
    var Release = await connection.GetClientAsync<ReleaseHttpClient>();

    var project = await Projects.GetProject(projectName);
    var releases = (await Release.GetReleaseDefinitionsAsync(project.Id)).Where(x => x.Path.StartsWith(path));
    Console.WriteLine($"Project: {project.Name} ({project.Id})");
    Console.WriteLine($"Releases: {releases.Count()} under path {path}");

    var results = new List<(string userType, string displayName, string userid, string email, string path, int allow, int deny)>();
    var ids = new Dictionary<string, Identity>();
    var memberships = new Dictionary<string, List<string>>();
    foreach (var release in releases)
    {
        var releaseAcls = await Security.QueryAccessControlListsAsync(guid, $"{project.Id}{release.Path.Replace("\\", "/").EnsureEndsWith("/")}{release.Id}", null, true, true);
        foreach (var x in releaseAcls)
        {
            x.Token = x.Token.Replace("/" + release.Id, "/" + release.Name);
            foreach (var y in x.AcesDictionary)
            {
                var id = ids.ContainsKey(y.Key.ToString()) ? ids[y.Key.ToString()] 
                    : (await Identity.ReadIdentitiesAsync(descriptors: new IdentityDescriptor[] { IdentityDescriptor.FromString(y.Key.ToString()) })).FirstOrDefault();
                ids.TryAdd(y.Key.ToString(), id);
                if (id != null && id.IsContainer)
                {
                    // Its a Team/Group
                    // Get the descriptor
                    var descriptors = await Graph.GetDescriptorAsync(id.Id);
                    var members = memberships.ContainsKey(descriptors.Value.ToString()) ? memberships[descriptors.Value.ToString()] 
                        : await Graph.GetUsersRecursive(descriptors.Value.ToString());
                    memberships.TryAdd(descriptors.Value.ToString(), members);

                    foreach (var member in members)
                    {
                        if (member.StartsWith("aadsp"))
                        {
                            var sp = await Graph.GetServicePrincipalAsync(member);
                            results.Add(("ServicePrincipal", sp.DisplayName, sp.ApplicationId, "", x.Token, y.Value.ExtendedInfo.EffectiveAllow, y.Value.ExtendedInfo.EffectiveDeny));
                        }
                        else
                        {
                            var graph_user = await Graph.GetUserAsync(member);
                            results.Add(("UserMember",graph_user.DisplayName, graph_user.Descriptor.Identifier, graph_user.MailAddress, x.Token, y.Value.ExtendedInfo.EffectiveAllow, y.Value.ExtendedInfo.EffectiveDeny));
                        }
                    }
                }
                else if (id != null && id.Descriptor.IdentityType.Equals("Microsoft.TeamFoundation.ServiceIdentity", StringComparison.OrdinalIgnoreCase))
                {
                    // It's a service account
                    results.Add(("ServiceAccount",id.DisplayName, id.Id.ToString().ToLowerInvariant(), !id.Properties.ContainsKey("Mail") ? "" : id.Properties["Mail"].ToString(), x.Token, y.Value.ExtendedInfo.EffectiveAllow, y.Value.ExtendedInfo.EffectiveDeny));
                }
                else if (id != null && !id.IsContainer)
                {
                    // It's a user
                    results.Add(("User", id.DisplayName, id.Id.ToString().ToLowerInvariant(), id.Properties["Mail"].ToString(), x.Token, y.Value.ExtendedInfo.EffectiveAllow, y.Value.ExtendedInfo.EffectiveDeny));
                }
            }
        }
    }

    var flattened = results.DistinctBy(x => x.userid+ "|" + x.path).ToList();

    var ns = await Security.QuerySecurityNamespacesAsync(guid);
    csv.WriteField("User Type");
    csv.WriteField("Release Pipeline");
    csv.WriteField("Principal Name");
    csv.WriteField("Principal Id");
    csv.WriteField("Email");
    foreach (var action in ns.First().Actions)
    {
        csv.WriteField($"{action.DisplayName} <{action.Bit}>");
    }
    csv.NextRecord();

    foreach (var r in flattened)
    {
        csv.WriteField(r.userType);
        csv.WriteField(r.path.Replace(project.Id.ToString(), project.Name));
        csv.WriteField(r.displayName);
        csv.WriteField(r.userid);
        csv.WriteField(r.email);
        foreach (var action in ns.First().Actions)
        {
            var allowed = r.allow.HasFlag(action.Bit);
            if (r.deny.HasFlag(action.Bit))
            {
                csv.WriteField("DENY");
            }
            else if (allowed)
            {
                csv.WriteField("ALLOW");
            }
            else
            {
                csv.WriteField("NOT SET");
            }
        }
        csv.NextRecord();
    }

}
catch (Exception ex)
{
    Console.WriteLine($"Error: {ex.Message}\r\n{ex.StackTrace}");
}