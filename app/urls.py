from django.urls import path
from . import views

urlpatterns = [
    path('', views.login_function, name='login'),  # Page racine = login
    path('login/', views.login_function, name='login'),
    path('register/', views.createUser, name="register"),
    path('verify/', views.verifyUser, name="verify"),
    path('verify-login/', views.verify_login, name='verify_login'),
    
    # Nouveaux endpoints
    path('patient/', views.patient_dashboard, name='patient'),
    path('medecin/', views.medecin_dashboard, name='medecin'),
    
    path('logout/', views.logout_function, name='logout')
]