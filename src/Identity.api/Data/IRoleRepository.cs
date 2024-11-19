using Identity.Api.Dtos;
using Identity.Api.Models;

namespace Identity.Api.Data
{
    public interface IRoleRepository
    {
        bool AddRole(RoleRequestDto? role);
        List<Role> GetAllRoles();
        Role? GetRoleById(Guid? roleId);
        Role? GetRoleByName(string? roleName);
        bool ModifyRole(Guid? roleId, RoleRequestDto newRoleData);
    }
}