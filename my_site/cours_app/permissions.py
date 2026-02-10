from rest_framework import permissions

class TeacherPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.role == 'teacher'

class StudentPermission(permissions.BasePermission):
    def has_permission(self, request, view):
        return request.user.role == 'student'