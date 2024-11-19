using Identity.Api.Dtos;
using Identity.Api.Models;

namespace Identity.Api.Data
{
    public interface IPermissionRepository
    {
        bool AddPermission(PermissionRequestDto? permission);
        List<Permission> GetAllPermissions();
        Permission? GetPermissionById(Guid? permissionId);
        Permission? GetPermissionByName(string? permissionName);
        bool ModifyPermission(Guid? permissionId, PermissionRequestDto? newPermissionData);
    }
}