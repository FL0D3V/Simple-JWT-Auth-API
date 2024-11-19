using Identity.Api.Data;
using Identity.Api.Helper;
using Identity.Api.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace Identity.Api.Controllers;


[ApiController]
[Route("api/[controller]")]
[Authorize(Roles = RoleTypeHelper.InternalAdmin)]
public class AdminController : ControllerBase
{
    private readonly ILogger<AdminController> _logger;
    private readonly IUserRepository _userRepo;
    private readonly IRoleRepository _roleRepository;
    private readonly IPermissionRepository _permissionRepository;

    public AdminController(IUserRepository userRepository, IRoleRepository roleRepository, IPermissionRepository permissionRepository, ILogger<AdminController> logger)
    {
        _userRepo = userRepository;
        _roleRepository = roleRepository;
        _permissionRepository = permissionRepository;
        _logger = logger;
    }


    [HttpGet("Permissions")]
    //[ValidateAntiForgeryToken]
    public ActionResult<List<Permission>> GetAllPermissions()
    {
        return _permissionRepository.GetAllPermissions();
    }


    [HttpGet("Roles")]
    //[ValidateAntiForgeryToken]
    public ActionResult<List<Role>> GetAllRoles()
    {
        return _roleRepository.GetAllRoles();
    }
}