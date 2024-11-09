using System.ComponentModel.DataAnnotations;

namespace finalAuth.Models.Authentication
{
    public class SignUp
    {
        public string? FullName { get; set; }
        [EmailAddress]
        public string? Email { get; set; }
        public string? Password { get; set; }
    }
}
