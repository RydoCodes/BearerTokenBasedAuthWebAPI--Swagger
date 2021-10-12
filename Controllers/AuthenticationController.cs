using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using TokenBasedAuthWebAPI.Data;
using TokenBasedAuthWebAPI.Data.Models;
using TokenBasedAuthWebAPI.Data.ViewModels;

namespace TokenBasedAuthWebAPI.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _rydousermanager;
        private readonly RoleManager<IdentityRole> _rydorolemanager;
        private readonly AppDbContext _rydocontext;
        private readonly IConfiguration _rydoconfiguration;
        private readonly TokenValidationParameters _rydotokenvalidationparameters;

        public AuthenticationController(UserManager<ApplicationUser> rydousermanager, RoleManager<IdentityRole> rydorolemanager, AppDbContext rydocontext, IConfiguration rydoconfiguration, TokenValidationParameters rydotokenvalidationparameters)
        {
            _rydousermanager = rydousermanager;
            _rydorolemanager = rydorolemanager;
            _rydocontext = rydocontext;
            _rydoconfiguration = rydoconfiguration;
            _rydotokenvalidationparameters = rydotokenvalidationparameters;
        }

        [HttpPost("register-user")]
        public async Task<IActionResult> Register([FromBody] RegisterVM registerVM)
        {
            if(!ModelState.IsValid)
            {
                return BadRequest("Please, provide all the required fields");
            }

            var userExists = await _rydousermanager.FindByEmailAsync(registerVM.EmailAddress);
            if(userExists!=null)
            {
                return BadRequest($"User {registerVM.EmailAddress} already exists");
            }

            ApplicationUser newUser = new ApplicationUser()
            {
                FirstName = registerVM.FirstName,
                LastName = registerVM.LastName,
                Email = registerVM.EmailAddress,
                UserName = registerVM.UserName,
                SecurityStamp = Guid.NewGuid().ToString()
            };

            var result = await _rydousermanager.CreateAsync(newUser, registerVM.Password);

            if(result.Succeeded)
            {
                return Ok("User Created");
            }
            else
            {
                return BadRequest("User could not be created");
            }
        }

        [HttpPost("login-user")]
        public async Task<IActionResult> Login([FromBody] LoginVM loginVM )
        {
            if(!ModelState.IsValid)
            {
                return BadRequest("Please provide all the required fields");
            }

            var userExists = await _rydousermanager.FindByEmailAsync(loginVM.EmailAddress);
            if(userExists!=null && await _rydousermanager.CheckPasswordAsync(userExists,loginVM.Password))
            {
                var tokenValue = await GenerateJWTTokenAsync(userExists);

                return Ok(tokenValue);
            }
            return Unauthorized();
        }

        private async Task<AuthResultVM> GenerateJWTTokenAsync(ApplicationUser user)
        {
            // First thing is to define authentication claims and claims are properties related to the user.
            var authClaims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name, user.UserName),
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim(JwtRegisteredClaimNames.Sub, user.Email),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            // Second is to get the secret key from the appsettings.json file

            var authSigningKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_rydoconfiguration["JWT:Secret"]));

            // Third we are going to define the actual token.
            // JwtSecurityToken - representing a JSON  Web Token (JWT)

            var token = new JwtSecurityToken(
                issuer: _rydoconfiguration["JWT:Issuer"],
                audience: _rydoconfiguration["JWT:Audience"],
                expires: DateTime.UtcNow.AddMinutes(1),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256));

            // By using the above token we can gnerate the JWT Token using below code.
            // JwtSecurityTokenHandler - Creating and validating Json Web Tokens.
            // WriteToken - Serializes a System.IdentityModel.Tokens.Jwt.JwtSecurityToken into a JWT in Compact Serialization Format.

            var jwttoken = new JwtSecurityTokenHandler().WriteToken(token);

            // --------Creating the Refresh Token --------

            var refreshtoken = new RefreshToken()
            {
                JwtId = token.Id,
                UserId = user.Id,
                DateAdded = DateTime.UtcNow,
                DateExpire = DateTime.UtcNow.AddMonths(6),
                Token = Guid.NewGuid().ToString() + "-" + Guid.NewGuid().ToString()
            };

            await _rydocontext.RefreshTokens.AddAsync(refreshtoken);
            await _rydocontext.SaveChangesAsync();

            var response = new AuthResultVM()
            {
                Token = jwttoken,
                RefreshToken = refreshtoken.Token,
                ExpiresAt = token.ValidTo
            };

            return response;
        }
    }
}