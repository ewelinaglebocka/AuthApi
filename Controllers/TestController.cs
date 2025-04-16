using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace AuthApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class TestController : ControllerBase
    {
        [HttpGet("public")]
        public IActionResult Public()
        {
            return Ok("To jest publiczny endpoint, dostępny bez logowania");
        }

        [HttpGet("secured")]
        [Authorize] 
        public IActionResult Secured()
        {
            var username = User.Identity?.Name;
            return Ok($"To jest zabezpieczony endpoint. Witaj, {username}!");
        }
    }
}
