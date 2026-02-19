using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Text.Json;

namespace ReservaDeVeiculos.WebApi.Middlewares
{
    public class UcdbAuthenticationOptions
    {
        public string Authority { get; set; } = "https://accounts.ucdb.br";
        public string ClientId { get; set; } = string.Empty;
        public bool RequireHttpsMetadata { get; set; } = true;
        public TimeSpan TokenCacheExpiry { get; set; } = TimeSpan.FromMinutes(5);
    }

    public class UcdbAuthenticationMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly HttpClient _httpClient;
        private readonly UcdbAuthenticationOptions _options;
        private readonly ILogger<UcdbAuthenticationMiddleware> _logger;
        private readonly IMemoryCache _tokenCache;

        public UcdbAuthenticationMiddleware(
            RequestDelegate next,
            IHttpClientFactory httpFactory,
            IOptions<UcdbAuthenticationOptions> options,
            ILogger<UcdbAuthenticationMiddleware> logger,
            IMemoryCache memoryCache)
        {
            _next = next;
            _httpClient = httpFactory.CreateClient("UcdbAuth");
            _httpClient.BaseAddress = new Uri(options.Value.Authority);
            _httpClient.Timeout = TimeSpan.FromSeconds(10);
            _options = options.Value;
            _logger = logger;
            _tokenCache = memoryCache;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            if (ShouldSkipAuthentication(context))
            {
                await _next(context);
                return;
            }
            var token = ExtractToken(context);

            if (string.IsNullOrEmpty(token))
            {
                _logger.LogInformation("No token found. IP: {IP}, Path: {Path}",
                    context.Connection.RemoteIpAddress, context.Request.Path);
                HandleUnauthenticated(context);
                return;
            }

            var isActive = await ValidateTokenWithCache(token);
            if (!isActive)
            {
                _logger.LogWarning("Invalid or expired token. IP: {IP}",
                    context.Connection.RemoteIpAddress);
                ClearTokenCookie(context);
                HandleUnauthenticated(context);
                return;
            }

            var userInfo = await GetUserInfoWithCache(token);
            if (userInfo != null)
            {
                context.User = CreateClaimsPrincipal(userInfo);
                _logger.LogInformation("User authenticated successfully: {Username}",
                    userInfo.Value.GetProperty("preferred_username").GetString());
            }

            await _next(context);
        }

        private bool ShouldSkipAuthentication(HttpContext context)
        {
            var path = context.Request.Path.Value?.ToLowerInvariant();
            var method = context.Request.Method.ToUpperInvariant();
            
            if (method == "OPTIONS")
                return true;
            
            var skipPaths = new[]
            {
                "/auth/callback",
            };

            return skipPaths.Any(skip => path?.StartsWith(skip) == true) ||
                   path?.Contains("/swagger") == true;
        }

        private string? ExtractToken(HttpContext context)
        {
            if (context.Request.Headers.ContainsKey("Authorization"))
            {
                var authHeader = context.Request.Headers["Authorization"].ToString();
                if (authHeader.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                    return authHeader.Substring(7);
            }

            if (context.Request.Cookies.TryGetValue("ucdb_token", out var cookieToken))
                return cookieToken;

            if (context.Request.Query.TryGetValue("token", out var queryToken))
                return queryToken;

            return null;
        }

        private void HandleUnauthenticated(HttpContext context)
        {
            // Check if this is an API request vs browser request
            var isApiRequest = IsApiRequest(context);

            if (isApiRequest)
            {
                // For API requests, return 401 Unauthorized JSON response
                context.Response.StatusCode = 401;
                context.Response.ContentType = "application/json";
                
                var response = new
                {
                    error = "unauthorized",
                    message = "Authentication required",
                    loginUrl = $"{_options.Authority}/Home/Login"
                };
                
                var json = JsonSerializer.Serialize(response, new JsonSerializerOptions
                {
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                });
                
                _logger.LogInformation("API request unauthorized, returning 401 JSON response");
                context.Response.WriteAsync(json);
                return;
            }

            // For browser requests, do the redirect
            var returnUrl = Uri.EscapeDataString($"{context.Request.Scheme}://{context.Request.Host}{context.Request.Path}{context.Request.QueryString}");
            var loginUrl = $"{_options.Authority}/Home/Login?returnUrl={returnUrl}";

            _logger.LogInformation("Browser request unauthorized, redirecting to: {LoginUrl}", loginUrl);
            context.Response.Redirect(loginUrl);
        }

        private bool IsApiRequest(HttpContext context)
        {
            // Check multiple indicators that this is an API request
            return context.Request.Path.StartsWithSegments("/api") ||
                   context.Request.Headers["X-Requested-With"] == "XMLHttpRequest" ||
                   context.Request.Headers["Accept"].ToString().Contains("application/json") ||
                   context.Request.Headers["Content-Type"].ToString().Contains("application/json") ||
                   context.Request.Headers.ContainsKey("Authorization");
        }

        private void ClearTokenCookie(HttpContext context)
        {
            context.Response.Cookies.Delete("ucdb_token", new CookieOptions
            {
                HttpOnly = true,
                Secure = _options.RequireHttpsMetadata,
                SameSite = SameSiteMode.Strict,
                Path = "/"
            });
        }

        private async Task<bool> ValidateTokenWithCache(string token)
        {
            var cacheKey = $"token_validation_{token.GetHashCode()}";

            if (_tokenCache.TryGetValue(cacheKey, out bool cachedResult))
                return cachedResult;

            var isValid = await ValidateToken(token);

            var cacheExpiry = isValid ? _options.TokenCacheExpiry : TimeSpan.FromMinutes(1);
            _tokenCache.Set(cacheKey, isValid, cacheExpiry);

            return isValid;
        }

        private async Task<bool> ValidateToken(string token)
        {
            // Removed try-catch to let exceptions bubble up to ErrorHandlingMiddleware
            var content = new FormUrlEncodedContent(new[] { new KeyValuePair<string, string>("token", token) });
            var response = await _httpClient.PostAsync("/keycloak/validatetoken", content);

            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("Token validation failed with status: {StatusCode}", response.StatusCode);
                return false;
            }

            var jsonResponse = await response.Content.ReadFromJsonAsync<JsonElement>();
            return jsonResponse.TryGetProperty("active", out var active) && active.GetBoolean();
        }

        private async Task<JsonElement?> GetUserInfoWithCache(string token)
        {
            var cacheKey = $"user_info_{token.GetHashCode()}";

            if (_tokenCache.TryGetValue(cacheKey, out JsonElement cachedUserInfo))
                return cachedUserInfo;

            var userInfo = await GetUserInfo(token);
            if (userInfo.HasValue)
            {
                _tokenCache.Set(cacheKey, userInfo.Value, _options.TokenCacheExpiry);
            }

            return userInfo;
        }

        private async Task<JsonElement?> GetUserInfo(string token)
        {
            // Removed try-catch to let exceptions bubble up to ErrorHandlingMiddleware
            var request = new HttpRequestMessage(HttpMethod.Get, "/keycloak/userinfo");
            request.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);

            var response = await _httpClient.SendAsync(request);
            if (!response.IsSuccessStatusCode)
            {
                _logger.LogWarning("User info request failed with status: {StatusCode}", response.StatusCode);
                return null;
            }

            var userInfo = await response.Content.ReadFromJsonAsync<JsonElement>();
            return userInfo;
        }

        private ClaimsPrincipal CreateClaimsPrincipal(JsonElement? userInfo)
        {
            var claims = new List<Claim>();

            if (userInfo?.TryGetProperty("preferred_username", out var username) == true)
                claims.Add(new Claim(ClaimTypes.Name, username.GetString() ?? ""));

            if (userInfo?.TryGetProperty("email", out var email) == true)
                claims.Add(new Claim(ClaimTypes.Email, email.GetString() ?? ""));

            if (userInfo?.TryGetProperty("sub", out var sub) == true)
                claims.Add(new Claim(ClaimTypes.NameIdentifier, sub.GetString() ?? ""));

            if (userInfo?.TryGetProperty("name", out var fullName) == true)
                claims.Add(new Claim(ClaimTypes.GivenName, fullName.GetString() ?? ""));

            if (userInfo?.TryGetProperty("groups", out var groups) == true && groups.ValueKind == JsonValueKind.Array)
            {
                foreach (var group in groups.EnumerateArray())
                    claims.Add(new Claim(ClaimTypes.Role, group.GetString() ?? ""));
            }

            var identity = new ClaimsIdentity(claims, "UcdbOAuth2");
            return new ClaimsPrincipal(identity);
        }
    }
}
