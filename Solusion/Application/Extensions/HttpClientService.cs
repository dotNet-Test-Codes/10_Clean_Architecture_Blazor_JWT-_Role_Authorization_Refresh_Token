using System.Net.Http.Headers;

namespace Application.Extensions
{
    public class HttpClientService(IHttpClientFactory httpClientFactory, LocalStorageService localStorageService)
    {
        public HttpClient GetPublicClient() => CreateClient();

        public async Task<HttpClient> GetPrivateClient()
        {
            try
            {
                var client = CreateClient();
                var localStorageDTO = await localStorageService.GetModelFromToken();
                if (string.IsNullOrEmpty(localStorageDTO.Token))
                    return client;

                client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue(Constant.HttpClientHeaderScheme, localStorageDTO.Token);
                return client;
            }
            catch { return new HttpClient(); }
        }

        #region Private
        private HttpClient CreateClient() => httpClientFactory!.CreateClient(Constant.HttpClientName);
        #endregion
    }
}
