using finalAuth.Models.Authentication;
using finalAuth.Repositories.AuthServices;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace finalAuth.Repositories
{
    public class AuthenticationRepository : IAuthenticationRepository
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly IEmailService _emailService;

        public AuthenticationRepository(UserManager<ApplicationUser> userManager,
            RoleManager<IdentityRole> roleManager, IConfiguration configuration,
            SignInManager<ApplicationUser> signInManager, IEmailService emailService)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
            _signInManager = signInManager;
            _emailService = emailService;
        }

        public async Task<object> SignUpAsync(SignUp signUp)
        {
            
            var user = new ApplicationUser()
            {
                FullName = signUp.FullName,
                Email = signUp.Email,
                UserName = signUp.Email,
                TwoFactorEnabled = true,
                SecurityStamp = Guid.NewGuid().ToString(),
                
            };
            var result =  await _userManager.CreateAsync(user, signUp.Password);
            if (await _roleManager.RoleExistsAsync("User"))
            {
                await _userManager.AddToRoleAsync(user, "User");
            }
            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);

            if (result.Succeeded)
            {
                return new
                {
                    token,
                    email = user.Email
                };

            }

            return result;
        }

        //Login
        public async Task<object> LoginAsync( SignIn signIn)
        {
            var user = await _userManager.FindByEmailAsync(signIn.Email!);
            var result = await _signInManager.PasswordSignInAsync(user, signIn.Password, false, true);
            if (!result.Succeeded)
            {
                return new { StatusCode = 401, message = "Unauthorised Access! Check you password again" };
            }
            if (user.TwoFactorEnabled)
            {
                await _signInManager.SignOutAsync();
                await _signInManager.PasswordSignInAsync(user, signIn.Password!, false, true);
                var token = await _userManager.GenerateTwoFactorTokenAsync(user, "Email");
                var otpMessage = new Message(new string[] { user.Email! }, "OTP Confirmation",token);
                _emailService.SendEmail(otpMessage);
                return new { StatusCode = 200, message = $"have send otp to {user.Email}",user.TwoFactorEnabled };

            }
            

            var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.Email),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                };

            var userRoles = await _userManager.GetRolesAsync(user);
            foreach (var role in userRoles)
            {
                authClaims.Add(new Claim(ClaimTypes.Role, role));
            }



            var jwtToken = GetToken(authClaims);

            return new
            {
                StatusCode = 200,
                token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
                expiration = jwtToken.ValidTo,
                user.TwoFactorEnabled
            };

        }

        //login-2FA
        public async Task<object> LoginWithOTPAsync( string code, string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            var signIn = await _signInManager.TwoFactorSignInAsync("Email", code, false, false);
            if (!signIn.Succeeded || user==null)
            {
                return new { StatusCode = 401, message="Your code Expire! try again." };
            }

            var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.Email),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                };

            var userRoles = await _userManager.GetRolesAsync(user);
            foreach (var role in userRoles)
            {
                authClaims.Add(new Claim(ClaimTypes.Role, role));
            }


            //GetToken private methon define in the bottom
            var jwtToken = GetToken(authClaims);

            return new
            {
                StatusCode = 200,
                token = new JwtSecurityTokenHandler().WriteToken(jwtToken),
                expiration = jwtToken.ValidTo,
                user.TwoFactorEnabled
            };

        }

        //forget password
        public async Task<string> ForgotPasswordAsync(string  email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            return token;

        }

        public async Task<IdentityResult> ResetPasswordAsync(ResetPassword resetPassword)
        {
            var user = await _userManager.FindByEmailAsync(resetPassword.Email!);
            
            var resetPassResult = await _userManager.ResetPasswordAsync(user!,resetPassword.Token!,resetPassword.Password!);
            return resetPassResult;
        }


        //Jwt token generate
        private JwtSecurityToken GetToken(List<Claim> authClaims)
        {
            var authSigninKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));
            var token = new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],
                audience: _configuration["JWT:ValidAudience"],
                expires: DateTime.Now.AddHours(3),
                claims: authClaims,
                signingCredentials: new SigningCredentials(authSigninKey, SecurityAlgorithms.HmacSha256)
                );
            return token;
        }

    }


}
