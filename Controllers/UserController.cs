using BackendAuthApi.Context;
using BackendAuthApi.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace BackendAuthApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly AppDbContext _authContext;
        public UserController(AppDbContext appDbContext)
        {
            _authContext= appDbContext;
            
        }


        [HttpPost("authenticate")]
        public async Task<IActionResult> Authenticate([FromBody] User userObj)
        {
            if (userObj == null)
            
                return BadRequest();
            
            var user = await _authContext.Users.FirstOrDefaultAsync(x =>x.UserName == userObj.UserName && x.Password == userObj.Password);
        if (user == null)
        
            return NotFound(new {Message="User is not found"} );
      

        user.Token= createjwt(user);

        return Ok(new{
                Message="Login Success",Token=user.Token
            });
        }

        [Authorize]
        [HttpGet]

        public async Task<ActionResult<User>> GetAllUsers()
        {
            return Ok(await _authContext.Users.ToListAsync());
        }


        [HttpPost("register")]
        public async Task<ActionResult> RegisterUser([FromBody] User userObj )
        { 
            if(userObj == null) 
                return BadRequest();
            await _authContext.Users.AddAsync(userObj);
            await _authContext.SaveChangesAsync();
            return Ok(new { Message = "USer has been registered" });
               
            }


        private string  createjwt(User user)
        {
            var jwttokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes("veryveryveryveryveryverysecret.....");

            var Identity = new ClaimsIdentity(new Claim[]
            {

                new Claim(ClaimTypes.Role,user.Role),
                new Claim(ClaimTypes.Name,$"{user.FirstName}:{user.LastName}"),
            });

            var credentials=new SigningCredentials(new SymmetricSecurityKey(key),SecurityAlgorithms.HmacSha256);
            var tokenDesciptor = new SecurityTokenDescriptor
            {
                Subject = Identity,
                Expires = DateTime.Now.AddDays(1),
                SigningCredentials = credentials,
            };
            var token=jwttokenHandler.CreateToken(tokenDesciptor);
             return jwttokenHandler.WriteToken(token);
        }

           
        
        }




    }

