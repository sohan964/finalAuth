using finalAuth.Models.Authentication;
using finalAuth.Repositories;
using finalAuth.Repositories.AuthServices;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace finalAuth.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly IAuthenticationRepository _authenticationRepository;
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IEmailService _emailService;
        private readonly RoleManager<IdentityRole> _roleManager;

        public AuthenticationController(IAuthenticationRepository authenticationRepository,
            UserManager<ApplicationUser> userManager, IEmailService emailService,
            RoleManager<IdentityRole> roleManager)
        {
            _authenticationRepository = authenticationRepository;
            _userManager = userManager;
            _emailService = emailService;
            _roleManager = roleManager;
        }

        [HttpPost("signup")] //createUser
        public async Task<IActionResult> CreateUser([FromBody] SignUp signUp)
        {
            var Result = await _authenticationRepository.SignUpAsync(signUp);

            var confirmationLink = Url.Action(nameof(ConfirmEmail), "Authentication", Result, Request.Scheme);
            var message = new Message(new string[] { signUp.Email! }, "Confirmation email link", confirmationLink!);
             _emailService.SendEmail(message);
            
            return Ok(Result);
        }

        [HttpGet("ConfirmEmaill")]
        public async Task<IActionResult> ConfirmEmail(string token, string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if(user == null)
            {
                return NotFound("the user not found");
            }

            var result = await _userManager.ConfirmEmailAsync(user, token);
            if(result.Succeeded)
            {
                return Ok(result);
            }
            return Unauthorized();
        }
        
        [HttpGet("user")]
        public async Task<IActionResult> CurrentUser()
        {
            var email = HttpContext.User?.Claims?.First()?.Value;
            if (email == null) return Unauthorized("Not a valide user");
            var user = await _userManager.FindByEmailAsync(email);
            if (user == null) return NotFound("Your not found");
            var role = await _userManager.GetRolesAsync(user);
            return Ok(new {
                user.FullName,
                user.Id,
                user.EmailConfirmed,
                user.Email,
                user.TwoFactorEnabled,
                role
            });
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] SignIn signIn)
        {
            var result = await _authenticationRepository.LoginAsync(signIn);
            return Ok(result);
        }

        [HttpPost("login-2FA")]
        public async Task<IActionResult> LoginWithOTP(string code, string email)
        {
            var result = await _authenticationRepository.LoginWithOTPAsync(code, email);
            return Ok(result);
        }

        [HttpPost("forget-password")]
        public async Task<IActionResult> ForgetPassword (string email)
        {
            var result = await _authenticationRepository.ForgotPasswordAsync(email);
            if(result == null)
            {
                return NotFound("account not found");
            }
            var message = new Message(new string[] { email }, "ResetPassword Token", result!);
            _emailService.SendEmail(message);
            return Ok(new {StatusCode=200, message="Check the email to get the Reset Token"});
        }

        [HttpPost("reset-password")]
        public async Task<IActionResult> ChangePassword(ResetPassword resetPassword)
        {
            var result = await _authenticationRepository.ResetPasswordAsync(resetPassword);
            if(!result.Succeeded)
            {
                foreach(var error  in result.Errors)
                {
                    //ModelState buildin here
                    ModelState.AddModelError(error.Code, error.Description);
                }
                return Ok(ModelState);
            }

            return Ok(new { StatusCode = 200, message = "password reset successfully" });
        }
    }
}
