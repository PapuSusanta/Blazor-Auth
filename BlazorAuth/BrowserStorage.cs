using Microsoft.JSInterop;
using System.Text.Json;

namespace BlazorAuth;


public class BrowserStorage(IJSRuntime jSRuntime) : IBrowserStorage
{
    private const string _storageType = "sessionStorage";
    private readonly IJSRuntime _jSRuntime = jSRuntime;

    public async Task SaveToStorage<T>(string key, T value)
    {
        var data = Serialize(value);
        await _jSRuntime.InvokeVoidAsync($"{_storageType}.setItem", key, data);
    }

    public async Task<T?> GetFromStorage<T>(string key)
    {
        var serializeData = await _jSRuntime.InvokeAsync<string?>($"{_storageType}.getItem", key);
        return Deserialize<T?>(serializeData);
    }

    public async Task RemoveFromStorage(string key)
        => await _jSRuntime.InvokeVoidAsync($"{_storageType}.removeItem", key);

    private static string Serialize<T>(T value) => JsonSerializer.Serialize(value);

    private static T? Deserialize<T>(string? jsonValue)
    {
        if (!string.IsNullOrEmpty(jsonValue))
            return JsonSerializer.Deserialize<T>(jsonValue);
        return default(T?);
    }

}

public interface IBrowserStorage
{
    Task SaveToStorage<T>(string key, T value);
    Task<T?> GetFromStorage<T>(string key);
    Task RemoveFromStorage(string key);
}