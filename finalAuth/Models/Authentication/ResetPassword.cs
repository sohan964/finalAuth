using System.ComponentModel.DataAnnotations;

namespace finalAuth.Models.Authentication
{
    public class ResetPassword
    {
        [Required]
        public string? Password { get; set; }

        [Compare("Password")]
        public string? PasswordConfirmation { get; set;}
        public string? Email { get; set;}
        public string? Token { get; set;}
    }
}
