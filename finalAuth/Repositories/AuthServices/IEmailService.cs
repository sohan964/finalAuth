using finalAuth.Models.Authentication;

namespace finalAuth.Repositories.AuthServices
{
    public interface IEmailService
    {
        void SendEmail(Message message);
    }
}
