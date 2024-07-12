using Application.Contracts;
using Application.DTOs.Request.Account;
using Application.DTOs.Response;
using Application.DTOs.Response.Account;
using Application.Extensions;
using Domain.Entity.Authentication;
using Infrastructure.Data;
using Mapster;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Infrastructure.Repos
{
    public class AccountRepository(RoleManager<IdentityRole> roleManager,
                                   UserManager<ApplicationUser> userManager,
                                   SignInManager<ApplicationUser> signInManager,
                                   IConfiguration config,
                                   AppDbContext context) : IAccount
    {
        public Task<GeneralResponse> ChangeUserRoleAsync(ChangeUserRoleRequestDTO model)
        {
            throw new NotImplementedException();
        }

        public async Task<GeneralResponse> CreateAccountAsync(CreateAccountDTO model)
        {
            try
            {
                if (await FindUserByEmailAsync(model.EmailAddress) != null)
                    return new GeneralResponse(false, "Sorry, user is already created");

                var user = new ApplicationUser()
                {
                    Name = model.Name,
                    UserName = model.EmailAddress,
                    Email = model.EmailAddress,
                    PasswordHash = model.Password
                };

                var result = await userManager.CreateAsync(user, model.Password);
                string error = CheckResponse(result);

                if (!string.IsNullOrEmpty(error))
                    return new GeneralResponse(false, error);

                var (flag, message) = await AssignUserToRole(user, new IdentityRole() { Name = model.Role });
                return new GeneralResponse(flag, message);
            }
            catch (Exception ex)
            {
                return new GeneralResponse(false, ex.Message);
            }
        }

        public async Task CreateAdmin()
        {
            try
            {
                if ((await FindRoleByNameAsync(Constant.Role.Admin)) != null) return;

                var admin = new CreateAccountDTO()
                {
                    Name = "Admin",
                    Password = "Admin@123",
                    EmailAddress = "admin@gmail.com",
                    Role = Constant.Role.Admin
                };

                await CreateAccountAsync(admin);
            }
            catch { }
        }

        public Task<GeneralResponse> CreateRoleAsync(CreateRoleDTO model)
        {
            throw new NotImplementedException();
        }

        public Task<IEnumerable<GetRoleDTO>> GetRoleAsync()
        {
            throw new NotImplementedException();
        }

        public async Task<IEnumerable<GetUsersWithRolesResponseDTO>> GetUsersWithRolesAsync()
        {
            var allUsers = await userManager.Users.ToListAsync();
            if (allUsers is null) return null!;

            var list = new List<GetUsersWithRolesResponseDTO>();

            foreach (var user in allUsers)
            {
                var getUserRole = (await userManager.GetRolesAsync(user)).FirstOrDefault();
                var getRoleInfo = await roleManager.Roles.FirstOrDefaultAsync(r => r.Name.ToLower() == getUserRole.ToLower());

                list.Add(new GetUsersWithRolesResponseDTO()
                {
                    Name = user.Name,
                    Email = user.Email,
                    RoleId = getRoleInfo.Id,
                    RoleName = getRoleInfo.Name
                });
            }

            return list;
        }

        public async Task<LoginResponse> LoginAccountAsync(LoginDTO model)
        {
            try
            {
                var user = await FindUserByEmailAsync(model.EmailAddress);
                if (user is null)
                    return new LoginResponse(false, "User not found");

                SignInResult result;

                try
                {
                    result = await signInManager.CheckPasswordSignInAsync(user, model.Password, false);
                }
                catch
                {
                    return new LoginResponse(false, "Invalid credentials");
                }

                if (!result.Succeeded)
                    return new LoginResponse(false, "Invalid credentials");

                string jwtToken = await GenerateToken(user);
                string refreshToken = GenerateRefreshToken();

                if (string.IsNullOrEmpty(jwtToken) || string.IsNullOrEmpty(refreshToken))
                    return new LoginResponse(false, "Error occurred while logging in account, please contact administration");
                else
                {
                    var saveResult = await SaveRefreshToken(user.Id, refreshToken);
                    if (saveResult.Flag)
                        return new LoginResponse(true, $"{user.Name} successfully logged in", jwtToken, refreshToken);
                    else
                        return new LoginResponse();
                }
            }
            catch (Exception ex)
            {
                return new LoginResponse(false, ex.Message);
            }
        }

        public async Task<LoginResponse> RefreshTokenAsync(RefreshTokenDTO model)
        {
            var token = await context.RefreshTokens.FirstOrDefaultAsync(t => t.Token == model.Token);
            if (token == null) return new LoginResponse();

            var user = await userManager.FindByIdAsync(token.UserID);
            string newToken = await GenerateToken(user);
            string newRefreshToken = GenerateRefreshToken();

            var saveResult = await SaveRefreshToken(user.Id, newRefreshToken);
            if (saveResult.Flag)
                return new LoginResponse(true, $"{user.Name} successfully re-logged in", newToken, newRefreshToken);
            else
                return new LoginResponse();
        }

        #region Private
        private async Task<ApplicationUser> FindUserByEmailAsync(string email) =>
            await userManager.FindByEmailAsync(email);

        private async Task<IdentityRole> FindRoleByNameAsync(string roleName) =>
            await roleManager.FindByNameAsync(roleName);

        private static string GenerateRefreshToken() =>
            Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));

        private async Task<string> GenerateToken(ApplicationUser user)
        {
            try
            {
                var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(config["Jwt:Key"]!));
                var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
                var userClaims = new[]
                {
                    new Claim(ClaimTypes.Name, user.Email),
                    new Claim(ClaimTypes.Email, user.Email),
                    new Claim(ClaimTypes.Role, (await userManager.GetRolesAsync(user)).FirstOrDefault().ToString()),
                    new Claim("FullName", user.Name)
                };

                var token = new JwtSecurityToken(issuer: config["Jwt:Issuer"],
                                                 audience: config["Jwt:Audience"],
                                                 claims: userClaims,
                                                 expires: DateTime.Now.AddMinutes(30),
                                                 signingCredentials: credentials);

                return new JwtSecurityTokenHandler().WriteToken(token);
            }
            catch { return null!; }
        }

        private async Task<GeneralResponse> AssignUserToRole(ApplicationUser user, IdentityRole role)
        {
            if (user is null || role is null) return new GeneralResponse(false, "Model state cannot be empty!");
            if (await FindRoleByNameAsync(role.Name) == null)
                await CreateRoleAsync(role.Adapt(new CreateRoleDTO()));

            IdentityResult result = await userManager.AddToRoleAsync(user, role.Name);
            string error = CheckResponse(result);

            if (!string.IsNullOrEmpty(error))
                return new GeneralResponse(false, error);
            else
                return new GeneralResponse(true, $"{user.Name} assigned to {role.Name} role");
        }

        private static string CheckResponse(IdentityResult result)
        {
            if (!result.Succeeded)
            {
                var errors = result.Errors.Select(x => x.Description);
                return string.Join(Environment.NewLine, errors);
            }

            return null!;
        }

        private async Task<GeneralResponse> SaveRefreshToken(string userId, string token)
        {
            try
            {
                var user = await context.RefreshTokens.FirstOrDefaultAsync(t => t.UserID == userId);

                if (user == null)
                    context.RefreshTokens.Add(new RefreshToken() { UserID = userId, Token = token });
                else
                    user.Token = token;

                await context.SaveChangesAsync();

                return new GeneralResponse(true, null!);
            }
            catch (Exception ex)
            {
                return new GeneralResponse(false, ex.Message);
            }
        }
        #endregion
    }
}
