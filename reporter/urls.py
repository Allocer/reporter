from django.conf.urls import url
from django.conf import settings
from django.conf.urls.static import static
from reporter import views

urlpatterns = [
    url(r'^$', views.index_view, name='index'),
    url(r'^new/malware_info$', views.new_report_view, name='empty_form'),
    url(r'^new/report$', views.list_of_all_reports_view, name='new_report'),
    url(r'^upload$', views.simple_upload, name='upload_file'),
    url(r'^new/report/pdf$', views.generate_pdf, name='generate_pdf'),
    url(r'^new/report/list$', views.list_view, name='list'),
    url(r'^new/report/delete$', views.delete_view, name='delete_report'),
    url(r'^help$', views.help_view, name='help'),
]

if settings.DEBUG:
    urlpatterns += static(settings.MEDIA_URL, document_root=settings.MEDIA_ROOT)
