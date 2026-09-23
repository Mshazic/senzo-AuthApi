using AuthApi.Models;
using AuthApi.DTOs;

namespace AuthApi.Services;
public interface IAuthService
{
    Task<AuthResult> RegisterAsync(RegisterRequest request);
    Task<AuthResult> LoginAsync(LoginRequest request);
    Task<AuthResult> RefreshTokenAsync(RefreshRequest request);
    Task<AuthResult> EnableMfaAsync(string userId);
    Task<AuthResult> VerifyMfaAsync(MfaVerifyRequest request);
    Task<AuthResult> DisableMfaAsync(string userId);
    Task<AuthResult> ExternalLoginAsync(ExternalLoginRequest request);  
}