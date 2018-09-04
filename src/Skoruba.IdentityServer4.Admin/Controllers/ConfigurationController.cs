using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Localization;
using Microsoft.Extensions.Logging;
using SF.Common;
using Skoruba.IdentityServer4.Admin.BusinessLogic.Dtos.Configuration;
using Skoruba.IdentityServer4.Admin.BusinessLogic.Helpers;
using Skoruba.IdentityServer4.Admin.BusinessLogic.Services;
using Skoruba.IdentityServer4.Admin.ExceptionHandling;

namespace Skoruba.IdentityServer4.Admin.Controllers
{
    [Authorize]
    [TypeFilter(typeof(ControllerExceptionFilterAttribute))]
    public class ConfigurationController : BaseController
    {
        private readonly IIdentityResourceService _identityResourceService;
        private readonly IApiResourceService _apiResourceService;
        private readonly IClientServiceV2 _clientService;
        private readonly IStringLocalizer<ConfigurationController> _localizer;

        public ConfigurationController(IIdentityResourceService identityResourceService,
            IApiResourceService apiResourceService,
            IClientServiceV2 clientService,
            IStringLocalizer<ConfigurationController> localizer,
            ILogger<ConfigurationController> logger)
            : base(logger)
        {
            _identityResourceService = identityResourceService;
            _apiResourceService = apiResourceService;
            _clientService = clientService;
            _localizer = localizer;
        }

        [HttpGet]
        [Route("[controller]/[action]")]
        [Route("[controller]/[action]/{id:int}")]
        public async Task<IActionResult> Client(int id)
        {
            if (id == 0)
            {
                var clientDto = _clientService.BuildClientViewModel();
                return View(clientDto);
            }

            var client = await _clientService.GetClientAsync(id);
            client = _clientService.BuildClientViewModel(client);

            return View(client);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Client(ClientDto client)
        {
            client = _clientService.BuildClientViewModel(client);

            if (!ModelState.IsValid)
            {
                return View(client);
            } 

            //Add new client
            if (client.Id == 0)
            {
                var clientId = await _clientService.AddClientAsync(client);
                SuccessNotification(string.Format(_localizer["SuccessAddClient"], client.ClientId), _localizer["SuccessTitle"]);

                return RedirectToAction(nameof(Client), new { Id = clientId });
            }

            //Update client
            await _clientService.UpdateClientAsync(client);
            SuccessNotification(string.Format(_localizer["SuccessUpdateClient"], client.ClientId), _localizer["SuccessTitle"]);

            return RedirectToAction(nameof(Clients));
        }

        [HttpGet]
        public async Task<IActionResult> ClientClone(int id)
        {
            if (id == 0) return NotFound();

            var clientDto = await _clientService.GetClientAsync(id);
            var client = _clientService.BuildClientCloneViewModel(id, clientDto);

            return View(client);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ClientClone(ClientCloneDto client)
        {
            if (!ModelState.IsValid)
            {
                return View(client);
            }

            var newClientId = await _clientService.CloneClientAsync(client);
            SuccessNotification(string.Format(_localizer["SuccessClientClone"], client.ClientId), _localizer["SuccessTitle"]);

            return RedirectToAction(nameof(Client), new { Id = newClientId });
        }

        [HttpGet]
        public async Task<IActionResult> ClientDelete(int id)
        {
            if (id == 0) return NotFound();

            var client = await _clientService.GetClientAsync(id);

            return View(client);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ClientDelete(ClientDto client)
        {
            await _clientService.RemoveClientAsync(client);

            SuccessNotification(_localizer["SuccessClientDelete"], _localizer["SuccessTitle"]);

            return RedirectToAction(nameof(Clients));
        }

        [HttpGet]
        public async Task<IActionResult> ClientClaims(int id, int? page)
        {
            if (id == 0) return NotFound();

            var claims = await _clientService.GetClientClaimsAsync(id, page ?? 1);

            return View(claims);
        }

        [HttpGet]
        public async Task<IActionResult> ClientProperties(int id, int? page)
        {
            if (id == 0) return NotFound();

            var properties = await _clientService.GetClientPropertiesAsync(id, page ?? 1);

            return View(properties);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ClientProperties(ClientPropertiesDto clientProperty)
        {
            if (!ModelState.IsValid)
            {
                return View(clientProperty);
            }

            await _clientService.AddClientPropertyAsync(clientProperty);
            SuccessNotification(string.Format(_localizer["SuccessAddClientProperty"], clientProperty.ClientId, clientProperty.ClientName), _localizer["SuccessTitle"]);

            return RedirectToAction(nameof(ClientProperties), new { Id = clientProperty.ClientId });
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ClientClaims(ClientClaimsDto clientClaim)
        {
            if (!ModelState.IsValid)
            {
                return View(clientClaim);
            }

            if( (await _clientService.AddClientClaimAsync(clientClaim)) != -1)
            {
                SuccessNotification(string.Format(_localizer["SuccessAddClientClaim"], clientClaim.Value, clientClaim.ClientName), _localizer["SuccessTitle"]);
            }

            return RedirectToAction(nameof(ClientClaims), new { Id = clientClaim.ClientId });
        }

        [HttpGet]
        public async Task<IActionResult> ClientClaimDelete(int claimid, int clientid)
        {
            if (claimid == 0) return NotFound();

            var clientClaim = await _clientService.GetClientClaimAsync(clientid, claimid);

            return View(nameof(ClientClaimDelete), clientClaim);
        }

        [HttpGet]
        public async Task<IActionResult> ClientPropertyDelete(int clientid, int propertyid)
        {
            if (propertyid == 0) return NotFound();

            var clientProperty = await _clientService.GetClientPropertyAsync(clientid, propertyid);

            return View(nameof(ClientPropertyDelete), clientProperty);
        }

        [HttpPost]
        public async Task<IActionResult> ClientClaimDelete(ClientClaimsDto clientClaim)
        {
            await _clientService.DeleteClientClaimAsync(clientClaim);
            SuccessNotification(_localizer["SuccessDeleteClientClaim"], _localizer["SuccessTitle"]);

            return RedirectToAction(nameof(ClientClaims), new { Id = clientClaim.ClientId });
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ClientPropertyDelete(ClientPropertiesDto clientProperty)
        {
            await _clientService.DeleteClientPropertyAsync(clientProperty);
            SuccessNotification(_localizer["SuccessDeleteClientProperty"], _localizer["SuccessTitle"]);

            return RedirectToAction(nameof(ClientProperties), new { Id = clientProperty.ClientId });
        }

        [HttpGet]
        public async Task<IActionResult> ClientSecrets(int id, int? page)
        {
            if (id == 0) return NotFound();

            var clientSecrets = await _clientService.GetClientSecretsAsync(id, page ?? 1);
            _clientService.BuildClientSecretsViewModel(clientSecrets);

            return View(clientSecrets);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ClientSecrets(ClientSecretsDto clientSecret)
        {
            await _clientService.AddClientSecretAsync(clientSecret);
            SuccessNotification(string.Format(_localizer["SuccessAddClientSecret"], clientSecret.ClientName), _localizer["SuccessTitle"]);

            return RedirectToAction(nameof(ClientSecrets), new { Id = clientSecret.ClientId });
        }

        [HttpGet]
        public async Task<IActionResult> ClientSecretDelete(int secretid, int clientid)
        {
            if (secretid == 0) return NotFound();

            var clientSecret = await _clientService.GetClientSecretAsync(clientid, secretid);

            return View(nameof(ClientSecretDelete), clientSecret);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ClientSecretDelete(ClientSecretsDto clientSecret)
        {
            await _clientService.DeleteClientSecretAsync(clientSecret);
            SuccessNotification(_localizer["SuccessDeleteClientSecret"], _localizer["SuccessTitle"]);

            return RedirectToAction(nameof(ClientSecrets), new { Id = clientSecret.ClientId });
        }

        [HttpGet]
        public async Task<IActionResult> SearchScopes(string scope, int limit = 0)
        {
            var scopes = await _clientService.GetScopesAsync(scope, limit);

            return Ok(scopes);
        }

        [HttpGet]
        public IActionResult SearchClaims(string claim, int limit = 0)
        {
            var claims = _clientService.GetStandardClaims(claim, limit);

            return Ok(claims);
        }

        [HttpGet]
        public IActionResult SearchGrantTypes(string grant, int limit = 0)
        {
            var grants = _clientService.GetGrantTypes(grant, limit);

            return Ok(grants);
        }

        [HttpGet]
        public async Task<IActionResult> Clients(int? page, string search)
        {
            ViewBag.Search = search;
            return View(await _clientService.GetClientsAsync(search, page ?? 1));
        }

        [Authorize(Policy = AccessControlContext.AdministrationPolicy)]
        [HttpGet]
        public async Task<IActionResult> IdentityResourceDelete(int id)
        {
            if (id == 0) return NotFound();

            var identityResource = await _identityResourceService.GetIdentityResourceAsync(id);

            return View(identityResource);
        }

        [Authorize(Policy = AccessControlContext.AdministrationPolicy)]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> IdentityResourceDelete(IdentityResourceDto identityResource)
        {
            await _identityResourceService.DeleteIdentityResourceAsync(identityResource);
            SuccessNotification(_localizer["SuccessDeleteIdentityResource"], _localizer["SuccessTitle"]);

            return RedirectToAction(nameof(IdentityResources));
        }

        [Authorize(Policy = AccessControlContext.AdministrationPolicy)]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> IdentityResource(IdentityResourceDto identityResource)
        {
            if (!ModelState.IsValid)
            {
                return View(identityResource);
            }

            identityResource = _identityResourceService.BuildIdentityResourceViewModel(identityResource);

            if (identityResource.Id == 0) await _identityResourceService.AddIdentityResourceAsync(identityResource);
            else await _identityResourceService.UpdateIdentityResourceAsync(identityResource);

            SuccessNotification(string.Format(_localizer["SuccessAddIdentityResource"], identityResource.Name), _localizer["SuccessTitle"]);

            return RedirectToAction(nameof(IdentityResources));
        }

        [Authorize(Policy = AccessControlContext.AdministrationPolicy)]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ApiResource(ApiResourceDto apiResource)
        {
            if (!ModelState.IsValid)
            {
                return View(apiResource);
            }

            ComboBoxHelpers.PopulateValuesToList(apiResource.UserClaimsItems, apiResource.UserClaims);

            if (apiResource.Id == 0) await _apiResourceService.AddApiResourceAsync(apiResource);
            else await _apiResourceService.UpdateApiResourceAsync(apiResource);

            SuccessNotification(string.Format(_localizer["SuccessAddApiResource"], apiResource.Name), _localizer["SuccessTitle"]);

            return RedirectToAction(nameof(ApiResources));
        }

        [Authorize(Policy = AccessControlContext.AdministrationPolicy)]
        [HttpGet]
        public async Task<IActionResult> ApiResourceDelete(int id)
        {
            if (id == 0) return NotFound();

            var apiResource = await _apiResourceService.GetApiResourceAsync(id);

            return View(apiResource);
        }

        [Authorize(Policy = AccessControlContext.AdministrationPolicy)]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ApiResourceDelete(ApiResourceDto apiResource)
        {
            await _apiResourceService.DeleteApiResourceAsync(apiResource);
            SuccessNotification(_localizer["SuccessDeleteApiResource"], _localizer["SuccessTitle"]);

            return RedirectToAction(nameof(ApiResources));
        }

        [Authorize(Policy = AccessControlContext.AdministrationPolicy)]
        [HttpGet]
        [Route("[controller]/[action]")]
        [Route("[controller]/[action]/{id:int}")]
        public async Task<IActionResult> ApiResource(int id)
        {
            if (id == 0)
            {
                var apiResourceDto = new ApiResourceDto();
                return View(apiResourceDto);
            }

            var apiResource = await _apiResourceService.GetApiResourceAsync(id);

            return View(apiResource);
        }

        [Authorize(Policy = AccessControlContext.AdministrationPolicy)]
        [HttpGet]
        public async Task<IActionResult> ApiSecrets(int id, int? page)
        {
            if (id == 0) return NotFound();

            var apiSecrets = await _apiResourceService.GetApiSecretsAsync(id, page ?? 1);
            _apiResourceService.BuildApiSecretsViewModel(apiSecrets);

            return View(apiSecrets);
        }

        [Authorize(Policy = AccessControlContext.AdministrationPolicy)]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ApiSecrets(ApiSecretsDto apiSecret)
        {
            if (!ModelState.IsValid)
            {
                return View(apiSecret);
            }

            await _apiResourceService.AddApiSecretAsync(apiSecret);
            SuccessNotification(_localizer["SuccessAddApiSecret"], _localizer["SuccessTitle"]);

            return RedirectToAction(nameof(ApiSecrets), new { Id = apiSecret.ApiResourceId });
        }

        [Authorize(Policy = AccessControlContext.AdministrationPolicy)]
        [HttpGet]
        public async Task<IActionResult> ApiScopes(int id, int? page, int? scope)
        {
            if (id == 0 || !ModelState.IsValid) return NotFound();

            if (scope == null)
            {
                var apiScopesDto = await _apiResourceService.GetApiScopesAsync(id, page ?? 1);

                return View(apiScopesDto);
            }
            else
            {
                var apiScopesDto = await _apiResourceService.GetApiScopeAsync(id, scope.Value);
                return View(apiScopesDto);
            }
        }

        [Authorize(Policy = AccessControlContext.AdministrationPolicy)]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ApiScopes(ApiScopesDto apiScope)
        {
            if (!ModelState.IsValid)
            {
                return View(apiScope);
            }

            _apiResourceService.BuildApiScopeViewModel(apiScope);

            if (apiScope.ApiScopeId == 0) await _apiResourceService.AddApiScopeAsync(apiScope);
            else await _apiResourceService.UpdateApiScopeAsync(apiScope);

            SuccessNotification(string.Format(_localizer["SuccessAddApiScope"], apiScope.Name), _localizer["SuccessTitle"]);

            return RedirectToAction(nameof(ApiScopes));
        }

        [Authorize(Policy = AccessControlContext.AdministrationPolicy)]
        [HttpGet]
        public async Task<IActionResult> ApiScopeDelete(int id, int scope)
        {
            if (id == 0 || scope == 0) return NotFound();

            var apiScope = await _apiResourceService.GetApiScopeAsync(id, scope);

            return View(nameof(ApiScopeDelete), apiScope);
        }

        [Authorize(Policy = AccessControlContext.AdministrationPolicy)]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ApiScopeDelete(ApiScopesDto apiScope)
        {
            await _apiResourceService.DeleteApiScopeAsync(apiScope);
            SuccessNotification(_localizer["SuccessDeleteApiScope"], _localizer["SuccessTitle"]);

            return RedirectToAction(nameof(ApiScopes), new { Id = apiScope.ApiResourceId });
        }

        [Authorize(Policy = AccessControlContext.AdministrationPolicy)]
        [HttpGet]
        public async Task<IActionResult> ApiResources(int? page, string search)
        {
            ViewBag.Search = search;
            var apiResources = await _apiResourceService.GetApiResourcesAsync(search, page ?? 1);

            return View(apiResources);
        }

        [Authorize(Policy = AccessControlContext.AdministrationPolicy)]
        [HttpGet]
        public async Task<IActionResult> IdentityResources(int? page, string search)
        {
            ViewBag.Search = search;
            var identityResourcesDto = await _identityResourceService.GetIdentityResourcesAsync(search, page ?? 1);

            return View(identityResourcesDto);
        }

        [Authorize(Policy = AccessControlContext.AdministrationPolicy)]
        [HttpGet]
        public async Task<IActionResult> ApiSecretDelete(int id)
        {
            if (id == 0) return NotFound();

            var clientSecret = await _apiResourceService.GetApiSecretAsync(id);

            return View(nameof(ApiSecretDelete), clientSecret);
        }

        [Authorize(Policy = AccessControlContext.AdministrationPolicy)]
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ApiSecretDelete(ApiSecretsDto apiSecret)
        {
            await _apiResourceService.DeleteApiSecretAsync(apiSecret);
            SuccessNotification(_localizer["SuccessDeleteApiSecret"], _localizer["SuccessTitle"]);

            return RedirectToAction(nameof(ApiSecrets), new { Id = apiSecret.ApiResourceId });
        }

        [Authorize(Policy = AccessControlContext.AdministrationPolicy)]
        [HttpGet]
        [Route("[controller]/[action]")]
        [Route("[controller]/[action]/{id:int}")]
        public async Task<IActionResult> IdentityResource(int id)
        {
            if (id == 0)
            {
                var identityResourceDto = new IdentityResourceDto();
                return View(identityResourceDto);
            }

            var identityResource = await _identityResourceService.GetIdentityResourceAsync(id);

            return View(identityResource);
        }
    }
}