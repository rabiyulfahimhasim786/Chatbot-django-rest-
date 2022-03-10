from django.contrib import admin
from django.contrib.auth import get_user_model
from django.contrib.auth.admin import UserAdmin as BaseUserAdmin
from django.contrib.auth.forms import (AdminPasswordChangeForm, UserChangeForm,
                                       UserCreationForm)
from django.utils.translation import gettext_lazy as _

from .models import (Categories, Domains, FullLengthKeyword, GeneralKeyword,
                     GramaticalKeyword, Keywords, Messages, Services,
                     StaticKeyword, Technologies, UserInfo)


class UserAdmin(BaseUserAdmin):
    form = UserChangeForm
    add_form = UserCreationForm
    change_password_form = AdminPasswordChangeForm
    ordering = ['id', ]
    list_display = ['email', 'phone', ]
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        (_('Personal Info'), {'fields': ('name', 'phone', 'user_type',)}),
        (_('Permission'), {
         'fields': ('is_active', 'is_staff', 'is_superuser', )}),
        (_('Important Dates'), {'fields': ('last_login', )}),
    )
    add_fieldsets = (
        (None, {
            # 'classes': ('wide',),
            'fields': ('email', 'password1', 'password2'),
        }),
    )


admin.site.register(get_user_model(), UserAdmin)
admin.site.register(Categories)
admin.site.register(Domains)
admin.site.register(FullLengthKeyword)
admin.site.register(GeneralKeyword)
admin.site.register(Keywords)
admin.site.register(Messages)
admin.site.register(Services)
admin.site.register(StaticKeyword)
admin.site.register(Technologies)
admin.site.register(GramaticalKeyword)
admin.site.register(UserInfo)

