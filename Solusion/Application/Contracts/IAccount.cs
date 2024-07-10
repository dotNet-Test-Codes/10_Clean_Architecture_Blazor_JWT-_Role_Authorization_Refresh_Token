using Application.DTOs.Request.Account;
using Application.DTOs.Response;
using Application.DTOs.Response.Account;

namespace Application.Contracts
{
    public interface IAccount
    {
        Task CreateAdmin();
        Task<IEnumerable<GetRoleDTO>> GetRoleAsync();
        Task<LoginResponse> LoginAccountAsync(LoginDTO model);
        Task<GeneralResponse> CreateRoleAsync(CreateRoleDTO model);
        Task<LoginResponse> RefreshTokenAsync(RefreshTokenDTO model);
        Task<GeneralResponse> CreateAccountAsync(CreateAccountDTO model);
        Task<IEnumerable<GetUsersWithRolesResponseDTO>> GetUsersWithRolesAsync();
        Task<GeneralResponse> ChangeUserRoleAsync(ChangeUserRoleRequestDTO model);
    }
}
