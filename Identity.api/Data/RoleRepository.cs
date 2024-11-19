using Identity.Api.Dtos;
using Identity.Api.Helper;
using Identity.Api.Models;

namespace Identity.Api.Data;


public class RoleRepository : IRoleRepository
{
    private readonly List<Role> Roles = new();


    public RoleRepository()
    {
        InitTestRoles();
    }


    private void InitTestRoles()
    {
        Roles.AddRange(new List<Role>()
        {
            new Role()
            {
                Id = Guid.NewGuid(),
                Name = RoleTypeHelper.InternalAdmin,
                Description = "Only for intern usage.",
                CreatedDate = DateTimeOffset.Now,
                ModifiedDate = DateTimeOffset.Now,
            },
            new Role()
            {
                Id = Guid.NewGuid(),
                Name = RoleTypeHelper.OrganizationHead,
                Description = "This role is set for users that have created a organization account and need to create employees.",
                CreatedDate = DateTimeOffset.Now,
                ModifiedDate = DateTimeOffset.Now,
            },
            new Role()
            {
                Id = Guid.NewGuid(),
                Name = RoleTypeHelper.SingleUser,
                Description = "This role is set for users which don't have a organization account.",
                CreatedDate = DateTimeOffset.Now,
                ModifiedDate = DateTimeOffset.Now,
            },
            new Role()
            {
                Id = Guid.NewGuid(),
                Name = RoleTypeHelper.OrganizationEmployee,
                Description = "This role is set for users that are created for a specific organization",
                CreatedDate = DateTimeOffset.Now,
                ModifiedDate = DateTimeOffset.Now,
            },
        });
    }


    public bool AddRole(RoleRequestDto? role)
    {
        if (role == null)
        {
            return false;
        }

        var check = Roles.Any(r => r.Name == role.Name);

        if (check)
        {
            return false;
        }

        var appRole = new Role()
        {
            Id = Guid.NewGuid(),
            Name = role.Name,
            Description = role.Description,
            CreatedDate = DateTimeOffset.UtcNow,
            ModifiedDate = DateTimeOffset.UtcNow,
        };

        Roles.Add(appRole);

        return true;
    }


    public bool ModifyRole(Guid? roleId, RoleRequestDto newRoleData)
    {
        if (newRoleData == null)
        {
            throw new ArgumentException("New role data must not be null!");
        }

        if (roleId == null || !roleId.HasValue || roleId == default)
        {
            return false;
        }

        var role = Roles.FirstOrDefault(r => r.Id.Equals(roleId));

        if (role == null)
        {
            return false;
        }

        role.Name = newRoleData.Name;
        role.Description = newRoleData.Description;

        return true;
    }


    public Role? GetRoleByName(string? roleName)
    {
        if (string.IsNullOrEmpty(roleName))
        {
            throw new ArgumentException("Role name was null or empty!");
        }

        return Roles.FirstOrDefault(r => r.Name == roleName);
    }


    public Role? GetRoleById(Guid? roleId)
    {
        if (roleId == null || !roleId.HasValue || roleId == default)
        {
            return null;
        }

        return Roles.FirstOrDefault(r => r.Id.Equals(roleId));
    }


    public List<Role> GetAllRoles()
    {
        return Roles.ToList();
    }
}
