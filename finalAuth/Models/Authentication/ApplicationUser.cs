using Microsoft.AspNetCore.Identity;

namespace finalAuth.Models.Authentication
{
    public class ApplicationUser: IdentityUser
    {
        public string? FullName { get; set; }
    }
}
