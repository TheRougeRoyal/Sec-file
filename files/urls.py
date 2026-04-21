from django.urls import path

from .views import (
    dashboard_view,
    download_file_view,
    files_list_view,
    upload_file_view,
    view_file_view,
)

app_name = 'files'

urlpatterns = [
    path('dashboard/', dashboard_view, name='dashboard'),
    path('upload/', upload_file_view, name='upload'),
    path('list/', files_list_view, name='list'),
    path('download/<int:file_id>/', download_file_view, name='download'),
    path('view/<int:file_id>/', view_file_view, name='view'),
]
