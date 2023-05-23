using Azure.Core;
using LoginApi.context;
using LoginApi.Helpers;
using LoginApi.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using System.Text.RegularExpressions;
using System.Text;
using System.IdentityModel.Tokens.Jwt;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authorization;

namespace LoginApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly AppDbContext dbcontext;
        public UserController(AppDbContext dbcontext)
        {
            this.dbcontext = dbcontext;
        }
        //login
        [HttpPost("authenticate")]
        public async Task<IActionResult> Authenticate([FromBody] User userObj)
        {
            if (userObj == null)
            {
                return BadRequest();
            }
            var user = await dbcontext.Users.FirstOrDefaultAsync(a => a.Email == userObj.Email);
            if (user == null)
            {
                return NotFound(new { Message = "User Not Found!" });
            }
            //check password
            if(!PasswordHasher.VerifyPassword(userObj.Password, user.Password))
                return BadRequest(new { Message = "PASSWORD INCORRECT!" });

            //token call
            user.Token = CreateToken(user);
            return Ok(new {
                Token=user.Token,
                Message = "Login Sucess!" });
        }





        [HttpPost("register")]
        public async Task<IActionResult> RegisterUser([FromBody] User userObj)
        {
            if (userObj == null)
                return BadRequest();

            if (await CheckUserEmailExistAsync(userObj.Email))
                return BadRequest(new { Message = "User email already Exists" });

            //check strength
            var passwd = CheckPasswordStrength(userObj.Password);
            if (!string.IsNullOrEmpty(passwd))
                return BadRequest(new { Message = passwd.ToString() });


            userObj.Password = PasswordHasher.HashPassword(userObj.Password);
            userObj.Role = "User";
            userObj.Token = "";
            //add into databse
            await dbcontext.Users.AddAsync(userObj);
            await dbcontext.SaveChangesAsync();
            return Ok(new { Message = "User Registered" });

        }

        //checkuser exists
        private Task<bool> CheckUserEmailExistAsync(string email)
            => dbcontext.Users.AnyAsync(x => x.Email == email);


        //chek strength
        private string CheckPasswordStrength(string password)
        {
            StringBuilder sb = new StringBuilder();
            if (password.Length < 8)
                sb.Append("Minimum password length should be 8" + Environment.NewLine);
            if (!(Regex.IsMatch(password, "[a-z]") && Regex.IsMatch(password, "[A-Z]") && Regex.IsMatch(password, "[0-9]")))
                sb.Append("Password should be Alphanumeric" + Environment.NewLine);
            if(!Regex.IsMatch(password, "[@,$,%]"))
             sb.Append("Password should contain special chars @ or $ or % " + Environment.NewLine);
            return sb.ToString();
        }


        //create token

        private string CreateToken(User user)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes("veryverysecret.....");
            var idenity = new ClaimsIdentity(new Claim[]
            {
                new Claim(ClaimTypes.Role,user.Role),
                new Claim(ClaimTypes.Name, $"{user.FirstName} {user.LastName}")
            });

            var credentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256);
            var tokenDescriptior = new SecurityTokenDescriptor
            {
                Subject = idenity,
                Expires = DateTime.Now.AddDays(1),
                SigningCredentials = credentials
            };
            var token=jwtTokenHandler.CreateToken(tokenDescriptior);
            return jwtTokenHandler.WriteToken(token);
            
        }

        [Authorize]
        [HttpGet]
        public async Task<ActionResult<User>> GetAllUser()
        {
            return Ok(await dbcontext.Users.ToListAsync());
        }
            

    }
}

