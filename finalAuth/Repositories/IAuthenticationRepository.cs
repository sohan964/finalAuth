using finalAuth.Models.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace finalAuth.Repositories
{
    public interface IAuthenticationRepository
    {
        Task<object> SignUpAsync(SignUp signUp);
        Task<object> LoginAsync( SignIn signIn);
        Task<object> LoginWithOTPAsync(string code, string email);
        Task<string> ForgotPasswordAsync(string email);
        Task<IdentityResult> ResetPasswordAsync(ResetPassword resetPassword);
    }
}
