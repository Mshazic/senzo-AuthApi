using System.Text;
using AuthApi.Data;
using AuthApi.Models;
using AuthApi.Services;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);

// Database
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection") ?? "Data Source=auth.db"));

// Identity
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequiredLength = 8;
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.User.RequireUniqueEmail = true;
    options.Tokens.AuthenticatorTokenProvider = TokenOptions.DefaultAuthenticatorProvider;
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();

// JWT + Social
var jwtKey = builder.Configuration["Jwt:Key"] ?? "ThisIsAVeryStrongSecretKeyThatShouldBeAtLeast32CharactersLong!";

builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = builder.Configuration["Jwt:Issuer"] ?? "AuthApi",
        ValidAudience = builder.Configuration["Jwt:Audience"] ?? "AuthApiClients",
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey)),
        ClockSkew = TimeSpan.Zero
    };
})
.AddGoogle(options =>
{
    options.ClientId = builder.Configuration["Authentication:Google:ClientId"] ?? "";
    options.ClientSecret = builder.Configuration["Authentication:Google:ClientSecret"] ?? "";
})
.AddMicrosoftAccount(options =>
{
    options.ClientId = builder.Configuration["Authentication:Microsoft:ClientId"] ?? "";
    options.ClientSecret = builder.Configuration["Authentication:Microsoft:ClientSecret"] ?? "";
});

builder.Services.AddAuthorization();
builder.Services.AddScoped<IAuthService, AuthService>();

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "Auth API", Version = "v1" });
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "JWT Authorization header using the Bearer scheme",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });
    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference { Type = ReferenceType.SecurityScheme, Id = "Bearer" }
            },
            Array.Empty<string>()
        }
    });
});

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    db.Database.Migrate();
}

// -------------------- Endpoints --------------------
app.MapPost("/register", async (RegisterRequest request, IAuthService auth) =>
{
    var result = await auth.RegisterAsync(request);
    return result.Succeeded ? Results.Ok(result.Data) : Results.BadRequest(new { result.Error });
});

app.MapPost("/login", async (LoginRequest request, IAuthService auth, HttpContext http) =>
{
    var result = await auth.LoginAsync(request, http.Connection.RemoteIpAddress?.ToString());
    if (!result.Succeeded)
    {
        if (result.Data is not null) // RequiresMfa case
            return Results.Json(result.Data, statusCode: 401);
        return Results.Unauthorized();
    }
    return Results.Ok(result.Data);
});

app.MapPost("/refresh", async (RefreshRequest request, IAuthService auth, HttpContext http) =>
{
    var result = await auth.RefreshTokenAsync(request.RefreshToken, http.Connection.RemoteIpAddress?.ToString());
    return result.Succeeded ? Results.Ok(result.Data) : Results.Unauthorized();
});

app.MapPost("/logout", async (RefreshRequest request, IAuthService auth) =>
{
    await auth.RevokeTokenAsync(request.RefreshToken);
    return Results.Ok(new { Message = "Logged out" });
});

app.MapPost("/mfa/enable", async (IAuthService auth, UserManager<ApplicationUser> userManager, HttpContext http) =>
{
    var user = await userManager.GetUserAsync(http.User);
    if (user is null) return Results.Unauthorized();

    var result = await auth.EnableMfaAsync(user);
    return result.Succeeded ? Results.Ok(result.Data) : Results.BadRequest(new { result.Error });
}).RequireAuthorization();

app.MapPost("/mfa/verify", async (MfaVerifyRequest request, IAuthService auth, UserManager<ApplicationUser> userManager, HttpContext http) =>
{
    var user = await userManager.GetUserAsync(http.User);
    if (user is null) return Results.Unauthorized();

    var result = await auth.VerifyAndEnableMfaAsync(user, request.Code);
    return result.Succeeded ? Results.Ok(result.Data) : Results.BadRequest(new { result.Error });
}).RequireAuthorization();

app.MapPost("/mfa/disable", async (MfaVerifyRequest request, IAuthService auth, UserManager<ApplicationUser> userManager, HttpContext http) =>
{
    var user = await userManager.GetUserAsync(http.User);
    if (user is null) return Results.Unauthorized();

    var result = await auth.DisableMfaAsync(user, request.Code);
    return result.Succeeded ? Results.Ok(result.Data) : Results.BadRequest(new { result.Error });
}).RequireAuthorization();

app.MapPost("/external-login", async (ExternalLoginRequest request, IAuthService auth, HttpContext http) =>
{
    var result = await auth.ExternalLoginAsync(request, http.Connection.RemoteIpAddress?.ToString());
    return result.Succeeded ? Results.Ok(result.Data) : Results.BadRequest(new { result.Error });
});

app.MapGet("/me", async (UserManager<ApplicationUser> userManager, HttpContext http) =>
{
    var user = await userManager.GetUserAsync(http.User);
    if (user is null) return Results.Unauthorized();

    return Results.Ok(new
    {
        user.Id,
        user.Email,
        user.FirstName,
        user.LastName,
        TwoFactorEnabled = await userManager.GetTwoFactorEnabledAsync(user)
    });
}).RequireAuthorization();

app.Run();