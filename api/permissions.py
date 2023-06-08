from rest_framework import permissions

# this use the permission for the admin , provider , seeker

class IsAdmin(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.role == 'admin'

class IsSolutionProvider(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.role == 'solution_provider'

class IsSolutionSeeker(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.role == 'solution_seeker'
