using Microsoft.VisualStudio.Services.Common;
using Microsoft.VisualStudio.Services.Graph;
using Microsoft.VisualStudio.Services.Graph.Client;
    using System.Collections.Generic;

public static class Ext
{

    public static int SumBitwise(this IEnumerable<int> numbers)
    {
        int sum = 0;
        foreach (var number in numbers)
        {
            sum |= number;
        }
        return sum;
    }
    public static string GetParameter(this string[] array, string value, string defaultValue = null, bool throwOnNull = true)
    {
        int index = Array.IndexOf(array, value);
        if (index >= 0 && index < array.Length - 1)
        {
            return array[index + 1];
        }
        else if (index >= 0) 
        {
            return defaultValue;
        }
        else if (throwOnNull)
        {
            throw new ArgumentException($"Value for {value} not found");
        }
        return defaultValue;
    }
    public static bool IsNumber(this string value)
    {
        return int.TryParse(value, out _);
    }
    public static bool AsBoolean(this string value)
    {
        return value == "1" || value == "" || value.ToLower().Trim() == "true"? true : false;
    }
    public static string EnsureEndsWith(this string value, string endingString)
    {
        if (!value.EndsWith(endingString))
        {
            value += endingString;
        }
        return value;
    }
    public static string ReplaceIfEndsWith(this string value, string a, string b, string c)
    {
        if (value.EndsWith(c))
        {
            return value.Replace(a, b);
        }
        return value;
    }

    public static async Task<List<string>> GetUsersRecursive(this GraphHttpClient Graph, string descriptor, List<string> data = null)
    {
        data = data ?? new List<string>();
        
        var result = await Graph.ListMembershipsAsync(descriptor, GraphTraversalDirection.Down, 1);
        foreach (var item in result)
        {
            if (item.MemberDescriptor.IsAadUserType()
                || item.MemberDescriptor.IsAadServicePrincipalType()
                || item.MemberDescriptor.IsMsaUserType()
                || item.MemberDescriptor.IsUserType())
            {
                data.Add(item.MemberDescriptor.ToString());
            }
            else if (item.MemberDescriptor.IsGroupType())
            {
                await Graph.GetUsersRecursive(item.MemberDescriptor, data);
            }
        }
        return data;
    }
    public static bool HasFlag(this int value, int flag)
    {
        return (value & flag) == flag;
    }
    public static void WriteDebug(string message)
    {
        if (Environment.GetEnvironmentVariable("VERBOSE").AsBoolean())
        {
            Console.WriteLine(message);
        }
    }
}
public class LoggingHandler : DelegatingHandler
{
    public LoggingHandler(HttpMessageHandler innerHandler)
        : base(innerHandler)
    {
    }

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        Console.WriteLine("Request:");
        Console.WriteLine(request.ToString());
        if (request.Content != null)
        {
            Console.WriteLine(await request.Content.ReadAsStringAsync());
        }
        Console.WriteLine();

        HttpResponseMessage response = await base.SendAsync(request, cancellationToken);

        Console.WriteLine("Response:");
        Console.WriteLine(response.ToString());
        if (response.Content != null)
        {
            Console.WriteLine(await response.Content.ReadAsStringAsync());
        }
        Console.WriteLine();

        return response;
    }
}