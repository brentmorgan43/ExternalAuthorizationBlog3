using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using ExternalAuthorization.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace ExternalAuthorization.Controllers
{
    public class AccountController : Controller
    {
        private readonly SignInManager<ApplicationUser> SignInManager;
        private readonly ExternalAuthData.ExternalAuthContext Context;
        public AccountController(SignInManager<ApplicationUser> SignInManager, ExternalAuthData.ExternalAuthContext DbContext)
        {
            this.SignInManager = SignInManager;
            Context = DbContext;
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult FacebookLogin()
        {
            // Request a redirect to the external login provider.
            var redirectUrl = "./Account/FacebookLoginCallback";
            var properties = new AuthenticationProperties();
            properties.RedirectUri = redirectUrl;
            properties.Items.Add("LoginProvider", "Facebook");
            var cr = new ChallengeResult("Facebook", properties);
            return cr;
        }

        public IActionResult FacebookLoginCallback()
        {
            return View("Register");
        }

        public async Task<JsonResult> RegisterUser(string FirstName, string LastName, string Email)
        {
            var info = await SignInManager.GetExternalLoginInfoAsync();
            ExternalAuthData.User user = new ExternalAuthData.User()
            {
                GivenName = FirstName,
                SurName = LastName,
                Email = Email,
                UserName = Email
            };

            if (user.Claims == null)
            {
                user.Claims = new List<ExternalAuthData.Claim>();
            }

            if (info.Principal.HasClaim(c => c.Type == ClaimTypes.NameIdentifier))
            {
                user.Claims.Add(new ExternalAuthData.Claim()
                {
                    ClaimType = "ProviderKey",
                    ClaimValue = info.Principal.FindFirstValue(ClaimTypes.NameIdentifier)
                });
            }
            if (info.Principal.HasClaim(c => c.Type == ClaimTypes.NameIdentifier))
            {
                user.Claims.Add(new ExternalAuthData.Claim()
                {
                    ClaimType = "ProviderName",
                    ClaimValue = info.Principal.FindFirst(ClaimTypes.NameIdentifier).Issuer
                });
            }
            if (info.Principal.HasClaim(c => c.Type == ClaimTypes.Surname))
            {
                user.Claims.Add(new ExternalAuthData.Claim()
                {
                    ClaimType = "Surname",
                    ClaimValue = info.Principal.FindFirstValue(ClaimTypes.Surname)
                });
            }
            if (info.Principal.HasClaim(c => c.Type == ClaimTypes.GivenName))
            {
                user.Claims.Add(new ExternalAuthData.Claim()
                {
                    ClaimType = "GivenName",
                    ClaimValue = info.Principal.FindFirstValue(ClaimTypes.GivenName)
                });
            }
            if (info.Principal.HasClaim(c => c.Type == ClaimTypes.Email))
            {
                user.Claims.Add(new ExternalAuthData.Claim()
                {
                    ClaimType = "Email",
                    ClaimValue = info.Principal.FindFirstValue(ClaimTypes.Email)
                });
            }

            Context.Users.Add(user);
            Context.SaveChanges();

            return Json(string.Empty);
        }

        public async Task<JsonResult> RetrieveExternalAuthClaims()
        {
            var info = await SignInManager.GetExternalLoginInfoAsync();

            Dictionary<string, string> claims = new Dictionary<string, string>();
            if (info.Principal.HasClaim(c => c.Type == ClaimTypes.Email))
            {
                claims.Add("Email", info.Principal.FindFirstValue(ClaimTypes.Email));
            }
            if (info.Principal.HasClaim(c => c.Type == ClaimTypes.GivenName))
            {
                claims.Add("FirstName", info.Principal.FindFirstValue(ClaimTypes.GivenName));
            }
            if (info.Principal.HasClaim(c => c.Type == ClaimTypes.Surname))
            {
                claims.Add("LastName", info.Principal.FindFirstValue(ClaimTypes.Surname));
            }

            return Json(claims);
        }
    }
}