from django.urls import path
from . import views
urlpatterns = [
    path('register/',views.createUser,name="register"),
    path('verify/',views.verifyUser,name="verify"),
    path('login/',views.login_function,name="login"),
    path('success/',views.success,name="success"),
    path('verify-login/', views.verify_login, name='verify_login'),
    path('logout/',views.logout_function,name='logout')
]
