using Identity.Api.Dtos;
using Identity.Api.Helper;
using Identity.Api.Models;

namespace Identity.Api.Data;


public class PermissionRepository : IPermissionRepository
{
    private readonly List<Permission> Permissions = new();


    public PermissionRepository()
    {
        InitTestPermissions();
    }


    private void InitTestPermissions()
    {
        Permissions.AddRange(new List<Permission>()
        {
            new Permission()
            {
                Id = Guid.NewGuid(),
                Scope = PermissionTypeHelper.AccessUserInfo,
                Description = "This allows the user to access his user informations.",
                CreatedDate = DateTimeOffset.Now,
                ModifiedDate = DateTimeOffset.Now,
            },
        });
    }


    public bool AddPermission(PermissionRequestDto? permission)
    {
        if (permission == null)
        {
            return false;
        }

        var check = Permissions.Any(r => r.Scope == permission.Scope);

        if (check)
        {
            return false;
        }

        var appPermission = new Permission()
        {
            Id = Guid.NewGuid(),
            Scope = permission.Scope,
            Description = permission.Description,
            CreatedDate = DateTimeOffset.UtcNow,
            ModifiedDate = DateTimeOffset.UtcNow,
        };

        Permissions.Add(appPermission);

        return true;
    }


    public bool ModifyPermission(Guid? permissionId, PermissionRequestDto? newPermissionData)
    {
        if (newPermissionData == null)
        {
            throw new ArgumentException("New permission data must not be null!");
        }

        if (permissionId == null || !permissionId.HasValue || permissionId == default)
        {
            return false;
        }

        var role = Permissions.FirstOrDefault(r => r.Id.Equals(permissionId));

        if (role == null)
        {
            return false;
        }

        role.Scope = newPermissionData.Scope;
        role.Description = newPermissionData.Description;

        return true;
    }


    public Permission? GetPermissionByName(string? permissionName)
    {
        if (string.IsNullOrEmpty(permissionName))
        {
            throw new ArgumentException("Permission name was null or empty!");
        }

        return Permissions.FirstOrDefault(r => r.Scope == permissionName);
    }


    public Permission? GetPermissionById(Guid? permissionId)
    {
        if (permissionId == null || !permissionId.HasValue || permissionId == default)
        {
            return null;
        }

        return Permissions.FirstOrDefault(r => r.Id.Equals(permissionId));
    }


    public List<Permission> GetAllPermissions()
    {
        return Permissions.ToList();
    }
}
