using Microsoft.AspNetCore.Components.Authorization;
using System.Security.Claims;
using System.Text.Json;

namespace BlazorAuth;

public class CustomAuthStateProvider : AuthenticationStateProvider
{
    private readonly IBrowserStorage _browserStorage;
    private const string _storageKey = "JWT_KEY";

    private const string AuthenticationType = nameof(AuthenticationType);
    private const string _token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0ZXN0IiwiaWQiOiIxIiwiTmFtZSI6IlNwaWRlciBtYW4iLCJSb2xlIjoiYWRtaW4ifQ.45EjBq5WR8maxGB1Qw32JJfFpk-jVsARtfCgP0tweI4";

    public CustomAuthStateProvider(IBrowserStorage browserStorage)
    {
        _browserStorage = browserStorage;
        AuthenticationStateChanged += CustomAuthenticationStateProvider_AuthenticationStateChanged;
    }

    public User LogInUser { get; set; } = new();
    private async void CustomAuthenticationStateProvider_AuthenticationStateChanged(Task<AuthenticationState> task)
    {
        var authState = await task;
        if (authState is not null)
        {
            var id = authState.User.FindFirst("id")?.Value;
            if (!string.IsNullOrWhiteSpace(id) && int.TryParse(id, out int ID) && ID > 0)
            {
                LogInUser = new User
                {
                    Id = ID,
                    Name = authState.User.FindFirst("Name")!.Value,
                    Role = authState.User.FindFirst("Role")!.Value,
                };
                return;
            }
        }
        LogInUser = new();
    }

    public override async Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        var user = await _browserStorage.GetFromStorage<string>(_storageKey);
        if (user == null)
        {
            LogInUser = new();
            return EmptyAuthState();
        }
        else
        {
            //LogInUser = user;
            return GetAuthenticationState(user);
        }
    }

    public async Task LoginAsync()
    {
        //LogInUser = new User
        //{
        //    Id = 1,
        //    Name = "Susanta Maji",
        //    Role = "Admin",
        //};
        await _browserStorage.SaveToStorage(_storageKey, _token);
        NotifyAuthenticationStateChanged(Task.FromResult(GetAuthenticationState(_token)));
    }

    public async Task LogoutAsync()
    {
        await _browserStorage.RemoveFromStorage(_storageKey);
        NotifyAuthenticationStateChanged(Task.FromResult(EmptyAuthState()));
    }

    private static AuthenticationState GetAuthenticationState(string Token)
    {
        //var claims = ParseClaimsFromJWT(token);
        //Claim[] claims = [
        //    new(ClaimTypes.NameIdentifier,user.Id.ToString()),
        //    new(ClaimTypes.Name,user.Name),
        //    new("Role",user.Role)
        //];

        var claims = ParseClaimsFromJWT(Token);

        var identity = new ClaimsIdentity(claims, AuthenticationType);
        var principal = new ClaimsPrincipal(identity);
        var state = new AuthenticationState(principal);
        return state;
    }

    private static AuthenticationState EmptyAuthState()
    {
        //Claim[] claims = [];
        var identity = new ClaimsIdentity();
        var principal = new ClaimsPrincipal(identity);
        var state = new AuthenticationState(principal);
        return state;
    }

    private static IEnumerable<Claim> ParseClaimsFromJWT(string jwt)
    {
        var payload = jwt.Split('.')[1];
        var jsonBytes = ParseBase64WithoutPadding(payload);
        var keyValuePairs = JsonSerializer.Deserialize<Dictionary<string, object>>(jsonBytes);
        return keyValuePairs!.Select(kv => new Claim(kv.Key, kv.Value.ToString()!));
    }

    private static byte[] ParseBase64WithoutPadding(string payload)
    {
        switch (payload.Length % 4)
        {
            case 2: payload += "=="; break;
            case 3: payload += "="; break;
        }
        return Convert.FromBase64String(payload);
    }
}