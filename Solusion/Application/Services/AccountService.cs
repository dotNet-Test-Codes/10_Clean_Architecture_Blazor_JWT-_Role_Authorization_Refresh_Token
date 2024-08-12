using Application.DTOs.Request.Account;
using Application.DTOs.Response;
using Application.DTOs.Response.Account;
using Application.Extensions;
using System.Net.Http.Json;

namespace Application.Services
{
    public class AccountService(HttpClientService httpClientService) : IAccountService
    {
        public Task<GeneralResponse> ChangeUserRoleAsync(ChangeUserRoleRequestDTO model)
        {
            throw new NotImplementedException();
        }

        public Task<GeneralResponse> CreateAccountAsync(CreateAccountDTO model)
        {
            throw new NotImplementedException();
        }

        public Task CreateAdmin()
        {
            throw new NotImplementedException();
        }

        public async Task CreateAdminAtFirstStart()
        {
            try
            {
                var client = httpClientService.GetPublicClient();
                await client.PostAsync(Constant.CreateAdminRoute, null);
            }
            catch {}
        }

        public Task<GeneralResponse> CreateRoleAsync(CreateRoleDTO model)
        {
            throw new NotImplementedException();
        }

        public async Task<IEnumerable<GetRoleDTO>> GetRoleAsync()
        {
            try
            {
                var privateClient = await httpClientService.GetPrivateClient();
                var response = await privateClient.GetAsync(Constant.GetRolesRoute);
                string error = CheckResponseStatus(response);
                if (!string.IsNullOrEmpty(error))
                    throw new Exception(error)!;

                var result = await response.Content.ReadFromJsonAsync<IEnumerable<GetRoleDTO>>();
                return result!;
            }
            catch (Exception ex)
            {
                throw new Exception(ex.Message)!;
            }
        }

        public Task<IEnumerable<GetUsersWithRolesResponseDTO>> GetUsersWithRolesAsync()
        {
            throw new NotImplementedException();
        }

        public async Task<LoginResponse> LoginAccountAsync(LoginDTO model)
        {
            try
            {
                var publicClient = httpClientService.GetPublicClient();
                var response = await publicClient.PostAsJsonAsync(Constant.LoginRoute, model);
                string error = CheckResponseStatus(response);
                if (!string.IsNullOrEmpty(error))
                    return new LoginResponse(Flag: false, Message: error);

                var result = await response.Content.ReadFromJsonAsync<LoginResponse>();
                return result!;
            }
            catch (Exception ex)
            {
                return new LoginResponse(Flag: false, Message: ex.Message);
            }
        }

        public async Task<GeneralResponse> RegisterAccountAsync(CreateAccountDTO model)
        {
            try
            {
                var publicClient = httpClientService.GetPublicClient();
                var response = await publicClient.PostAsJsonAsync(Constant.RegisterRoute, model);
                string error = CheckResponseStatus(response);
                if (!string.IsNullOrEmpty(error))
                    return new GeneralResponse(Flag: false, Message: error);

                var result = await response.Content.ReadFromJsonAsync<GeneralResponse>();
                return result!;
            }
            catch (Exception ex)
            {
                return new GeneralResponse(Flag: false, Message: ex.Message);
            }
        }

        public Task<LoginResponse> RefreshTokenAsync(RefreshTokenDTO model)
        {
            throw new NotImplementedException();
        }

        #region Private
        private static string CheckResponseStatus(HttpResponseMessage response)
        {
            if (!response.IsSuccessStatusCode)
                return $"Sorry unknown error occured. {Environment.NewLine}Error Description: {Environment.NewLine}Status Code: " +
                       $"{response.StatusCode}{Environment.NewLine}Reason Phrase: {response.ReasonPhrase}";
            else
                return null!;
        }
        #endregion
    }
}
