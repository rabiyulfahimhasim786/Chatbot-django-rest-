from rest_framework.permissions import BasePermission
from rest_framework.permissions import IsAdminUser, SAFE_METHODS


class IsAdminUserOrReadOnly(IsAdminUser):

    def has_permission(self, request, view):
        is_admin = super(
            IsAdminUserOrReadOnly,
            self).has_permission(request, view)
        # Python3: is_admin = super().has_permission(request, view)
        return request.method in SAFE_METHODS or is_admin


class IsAllowedToWrite(BasePermission):
    # def has_permission(self, request, view):
    #     safe_method_for_customer = ['GET', 'PUT']
    #     safe_method_for_ananymous = ['POST', 'PUT']
    #     safe_method_for_admin = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']
    #
    #     if request.user.user_type == "customer" and request.method in safe_method_for_customer:
    #         return True
    #     elif request.user.user_type == "ananymous" and request.method in safe_method_for_ananymous:
    #         return True
    #     elif request.user.is_staff and request.method in safe_method_for_admin:
    #         return True
    #     else:
    #         return False
    def has_permission(self, request, view):
        return request.user and request.user.is_authenticated

    def check_object_permission(self, user, obj):
        if user.user_type is not None:
            return True
        return (user and user.is_authenticated() and (user.is_staff or obj == user))

    def has_object_permission(self, request, view, obj):
        return self.check_object_permission(request.user, obj)
