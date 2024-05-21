from django.contrib import admin
from django.contrib.auth.admin import UserAdmin
from .models import Profile
from django.utils.html import format_html


#___________________________________________________________  AccountAdmin
class AccountAdmin(UserAdmin):

      def thumbnail(self, object):
            return format_html('<img src="{}" width="30" style="border-radius:50%;">'.format(object.profile_picture.url))
      thumbnail.short_description = 'Profile Picture'

      list_display       = ('thumbnail','username', 'email','first_name','last_name','last_login','date_joined','is_active')
      list_display_links = ('username', 'email')
      readonly_fields    = ( 'last_login', 'date_joined')
      ordering           = ('-date_joined',)
      

      # Added due to custom class
      filter_horizontal  = ()
      list_filter        = ()
      fieldsets          = ()


admin.site.register(AccountAdmin, UserAdmin)
