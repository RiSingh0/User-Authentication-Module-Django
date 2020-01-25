from django.conf.urls import url,include
#from django.urls import path
from dappx import views
from django.contrib.auth.views import PasswordResetView,PasswordResetConfirmView
# SET THE NAMESPACE!
app_name = 'dappx'
# Be careful setting the name to just /login use userlogin instead!
urlpatterns=[
    url('register/', views.register, name='register'),
    url('user_login/', views.user_login, name='user_login'),
    url('google_login/', views.google_login, name='google_login'),
    url('special/', views.special, name='special'),
    url('profile/', views.profile, name='profile'),
    url('change_password/', views.password, name='change_password'),
    url('logout/', views.user_logout, name='logout'),
    url('delete_account/', views.delete_account, name='delete_account'),
    url(r'^', include('django.contrib.auth.urls')),
    url('password_reset/', PasswordResetView.as_view(), name='password_reset'),
    url('reset/<uidb64>/<token>/', PasswordResetConfirmView.as_view(success_url='dappx:password_reset_complete'), name='password_reset_confirm'),
    url(r'^activate/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$',views.activate, name='activate'),
    url(r'^deactivate/(?P<uidb64>[0-9A-Za-z_\-]+)/(?P<token>[0-9A-Za-z]{1,13}-[0-9A-Za-z]{1,20})/$',views.deactivate, name='deactivate'),
]