using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;

// This authorization handler enforces the ownership rule for student resources.
// It checks whether the current user is either:
// - An Admin (full access), OR
// - The owner of the student record being requested
//
// This handler is used by the "StudentOwnerOrAdmin" policy.
public class StudentOwnerOrAdminHandler
    : AuthorizationHandler<StudentOwnerOrAdminRequirement, int>
{
    // This method is called automatically by ASP.NET Core
    // whenever the "StudentOwnerOrAdmin" policy is evaluated.
    //
    // Parameters:
    // - context: contains the authenticated user and authorization state
    // - requirement: represents the ownership rule (Owner OR Admin)
    // - studentId: the resource being protected (route parameter)
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        StudentOwnerOrAdminRequirement requirement,
        int studentId)
    {
        // First rule: Admin override
        // If the authenticated user has the Admin role,
        // they are allowed to access any student record.
        if (context.User.IsInRole("Admin"))
        {
            // Mark the requirement as satisfied
            context.Succeed(requirement);
            return Task.CompletedTask;
        }

        // Second rule: Ownership check
        // Extract the authenticated user's ID from the JWT claims.
        // This value was added to the token during login
        // and validated by the JWT middleware.
        var userId = context.User.FindFirstValue(ClaimTypes.NameIdentifier);

        // Compare the authenticated user's ID with the requested student ID.
        // If they match, the user owns the resource.
        if (int.TryParse(userId, out int authenticatedStudentId) &&
            authenticatedStudentId == studentId)
        {
            // Ownership confirmed, authorization succeeds
            context.Succeed(requirement);
        }

        // If neither admin nor owner conditions are met,
        // the requirement is not satisfied and access will be denied.
        // ASP.NET Core will automatically return 403 Forbidden.
        return Task.CompletedTask;
    }
}
