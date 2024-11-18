from django.contrib import admin
from .models import MaternalRecord
from .models import ChildRecord

class MaternalRecordAdmin(admin.ModelAdmin):
    list_display = ('first_name', 'middle_name', 'last_name', 'status', 'date_entered', 'birthday', 'age', 'nutritional_status', 'four_ps_member')
    list_filter = ('status', 'nutritional_status', 'four_ps_member')
    search_fields = ('first_name', 'last_name', 'muac')
    ordering = ('-date_entered',)

admin.site.register(MaternalRecord, MaternalRecordAdmin)
class ChildRecordAdmin(admin.ModelAdmin):
    list_display = ('first_name', 'middle_name', 'last_name', 'gender', 'birthday', 'age_in_months', 'weight', 'height')
    list_filter = ('gender', 'weight_for_age_status', 'height_for_age_status', 'weight_for_lt_ht_status')
    search_fields = ('first_name', 'middle_name', 'last_name', 'gender')
    ordering = ('last_name', 'first_name')
    
admin.site.register(ChildRecord, ChildRecordAdmin)
