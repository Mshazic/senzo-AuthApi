using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using AuthApi.Data;
using AuthApi.DTOs;
using AuthApi.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

namespace AuthApi.Services;

public class AuthService : IAuthService
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly ApplicationDbContext _db;
    private readonly IConfiguration _config;

    public AuthService(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        ApplicationDbContext db,
        IConfiguration config)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _db = db;
        _config = config;
    }

    public async Task<AuthResult> RegisterAsync(RegisterRequest request)
    {
        var user = new ApplicationUser
        {
            UserName = request.Email,
            Email = request.Email,
            FirstName = request.FirstName,
            LastName = request.LastName
        };

        var result = await _userManager.CreateAsync(user, request.Password);
        if (!result.Succeeded)
            return new AuthResult(false, string.Join(", ", result.Errors.Select(e => e.Description)));

        return new AuthResult(true, Data: new { Message = "User registered successfully" });
    }

    public async Task<AuthResult> LoginAsync(LoginRequest request, string? ipAddress)
    {
        var user = await _userManager.FindByEmailAsync(request.Email);
        if (user is null)
            return new AuthResult(false, "Invalid credentials");

        var result = await _signInManager.CheckPasswordSignInAsync(user, request.Password, lockoutOnFailure: true);
        if (!result.Succeeded)
            return new AuthResult(false, "Invalid credentials");

        // MFA check
        if (await _userManager.GetTwoFactorEnabledAsync(user))
        {
            if (string.IsNullOrWhiteSpace(request.MfaCode))
                return new AuthResult(false, "MFA code required", new { RequiresMfa = true });

            var isValid = await _userManager.VerifyTwoFactorTokenAsync(
                user, TokenOptions.DefaultAuthenticatorProvider, request.MfaCode);

            if (!isValid)
                return new AuthResult(false, "Invalid MFA code");
        }

        var tokens = await GenerateTokensAsync(user, ipAddress);
        return new AuthResult(true, Data: tokens);
    }

    public async Task<AuthResult> RefreshTokenAsync(string refreshToken, string? ipAddress)
    {
        var existing = await _db.RefreshTokens
            .Include(x => x.User)
            .FirstOrDefaultAsync(x => x.Token == refreshToken);

        if (existing is null || !existing.IsActive)
            return new AuthResult(false, "Invalid or expired refresh token");

        // Rotate
        existing.RevokedAt = DateTime.UtcNow;

        var newTokens = await GenerateTokensAsync(existing.User, ipAddress);
        existing.ReplacedByToken = newTokens.RefreshToken;

        await _db.SaveChangesAsync();
        return new AuthResult(true, Data: newTokens);
    }

    public async Task RevokeTokenAsync(string refreshToken)
    {
        var token = await _db.RefreshTokens.FirstOrDefaultAsync(x => x.Token == refreshToken);
        if (token is null) return;

        token.RevokedAt = DateTime.UtcNow;
        await _db.SaveChangesAsync();
    }

    public async Task<AuthResult> EnableMfaAsync(ApplicationUser user)
    {
        var key = await _userManager.GetAuthenticatorKeyAsync(user);
        if (string.IsNullOrEmpty(key))
        {
            await _userManager.ResetAuthenticatorKeyAsync(user);
            key = await _userManager.GetAuthenticatorKeyAsync(user);
        }

        var email = await _userManager.GetEmailAsync(user) ?? user.UserName!;
        var uri = GenerateQrCodeUri(email, key!);

        return new AuthResult(true, Data: new MfaEnableResponse(FormatKey(key!), uri));
    }

    public async Task<AuthResult> VerifyAndEnableMfaAsync(ApplicationUser user, string code)
    {
        var isValid = await _userManager.VerifyTwoFactorTokenAsync(
            user, TokenOptions.DefaultAuthenticatorProvider, code);

        if (!isValid)
            return new AuthResult(false, "Invalid MFA code");

        await _userManager.SetTwoFactorEnabledAsync(user, true);
        return new AuthResult(true, Data: new { Message = "MFA enabled successfully" });
    }

    public async Task<AuthResult> DisableMfaAsync(ApplicationUser user, string code)
    {
        var isValid = await _userManager.VerifyTwoFactorTokenAsync(
            user, TokenOptions.DefaultAuthenticatorProvider, code);

        if (!isValid)
            return new AuthResult(false, "Invalid MFA code");

        await _userManager.SetTwoFactorEnabledAsync(user, false);
        await _userManager.ResetAuthenticatorKeyAsync(user);

        return new AuthResult(true, Data: new { Message = "MFA disabled" });
    }

    public async Task<AuthResult> ExternalLoginAsync(ExternalLoginRequest request, string? ipAddress)
    {
        // NOTE: In production you MUST validate the IdToken properly
        // (Google.Apis.Auth, Microsoft Identity, etc.)

        var user = await _userManager.FindByEmailAsync(request.Email);

        if (user is null)
        {
            user = new ApplicationUser
            {
                UserName = request.Email,
                Email = request.Email,
                EmailConfirmed = true,
                FirstName = request.Name
            };

            var createResult = await _userManager.CreateAsync(user);
            if (!createResult.Succeeded)
                return new AuthResult(false, string.Join(", ", createResult.Errors.Select(e => e.Description)));

            await _userManager.AddLoginAsync(user,
                new UserLoginInfo(request.Provider, request.ProviderKey, request.Provider));
        }

        var tokens = await GenerateTokensAsync(user, ipAddress);
        return new AuthResult(true, Data: tokens);
    }

    // -------------------- Private helpers --------------------

    private async Task<TokenResponse> GenerateTokensAsync(ApplicationUser user, string? ipAddress)
    {
        var accessToken = GenerateJwtToken(user);

        var refreshToken = new RefreshToken
        {
            Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
            UserId = user.Id,
            ExpiresAt = DateTime.UtcNow.AddDays(7),
            CreatedByIp = ipAddress
        };

        _db.RefreshTokens.Add(refreshToken);
        await _db.SaveChangesAsync();

        return new TokenResponse(accessToken, refreshToken.Token, "Bearer", 3600);
    }

    private string GenerateJwtToken(ApplicationUser user)
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]!));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, user.Id),
            new(ClaimTypes.Email, user.Email ?? ""),
            new(ClaimTypes.Name, user.UserName ?? ""),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

        var token = new JwtSecurityToken(
            issuer: _config["Jwt:Issuer"],
            audience: _config["Jwt:Audience"],
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(60),
            signingCredentials: creds);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    private static string GenerateQrCodeUri(string email, string unformattedKey)
    {
        const string issuer = "AuthApi";
        return $"otpauth://totp/{Uri.EscapeDataString(issuer)}:{Uri.EscapeDataString(email)}" +
               $"?secret={unformattedKey}&issuer={Uri.EscapeDataString(issuer)}&digits=6";
    }

    private static string FormatKey(string unformattedKey)
    {
        var result = new StringBuilder();
        int pos = 0;
        while (pos + 4 < unformattedKey.Length)
        {
            result.Append(unformattedKey.AsSpan(pos, 4)).Append(' ');
            pos += 4;
        }
        if (pos < unformattedKey.Length)
            result.Append(unformattedKey.AsSpan(pos));

        return result.ToString().ToLowerInvariant();
    }
}