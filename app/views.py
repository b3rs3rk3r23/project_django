from django.contrib import messages
from django.http.response import HttpResponse, HttpResponseRedirect
from django.shortcuts import render
from . forms import CreateUser
from django.core.mail import send_mail
from django.conf import settings
from django.contrib.auth.models import User
import random
from .models import PreRegistration
from .forms import VerifyForm,LoginForm
from django.contrib.auth import login,logout,authenticate
from django.shortcuts import redirect
# Create your views here.

def creatingOTP():
    otp = ""
    for i in range(11):
        otp+= f'{random.randint(0,9)}'
    return otp

def root_view(request):
    if request.user.is_authenticated:
        return redirect('success')
    return redirect('login')

def sendEmail(email):
    otp = creatingOTP()
    send_mail(
    'One Time Password',
    f'Your OTP pin is {otp}',
    settings.EMAIL_HOST_USER,
    [email],
    fail_silently=False,
    )
    return otp


def createUser(request):
    if not request.user.is_authenticated:
        if request.method == 'POST':
            form = CreateUser(request.POST)
            if form.is_valid():
                email = form.cleaned_data['email']
                otp = sendEmail(email)
                dt = PreRegistration(first_name=form.cleaned_data['first_name'],last_name=form.cleaned_data['last_name'],username= form.cleaned_data['username'],email=email,otp=otp,password1 = form.cleaned_data['password1'],password2 = form.cleaned_data['password2'])
                dt.save()
                return HttpResponseRedirect('/verify/')
                
                
        else:
            form = CreateUser()
        return render(request,"html/register.html",{'form':form})
    else:
        return HttpResponseRedirect('/success/')




def verify_login(request):
    if not request.user.is_authenticated:
        if 'otp_user_id' not in request.session:
            return HttpResponseRedirect('/login/')  # Redirige si pas de tentative de connexion
        
        if request.method == 'POST':
            entered_otp = request.POST.get('otp', '')
            saved_otp = request.session.get('login_otp', '')
            
            if entered_otp == saved_otp:
                # OTP correct, connecte l'utilisateur
                user_id = request.session['otp_user_id']
                user = User.objects.get(id=user_id)
                login(request, user)
                
                # Nettoie la session
                del request.session['login_otp']
                del request.session['otp_user_id']
                
                return HttpResponseRedirect('/success/')
            else:
                messages.error(request, "OTP incorrect")
                return HttpResponseRedirect('/verify-login/')
        
        return render(request, 'html/verify_login.html')
    else:
        return HttpResponseRedirect('/success/')


def verifyUser(request):
    if not request.user.is_authenticated:
        if request.method == 'POST':
            form = VerifyForm(request.POST)
            if form.is_valid():
                otp = form.cleaned_data['otp']
                data = PreRegistration.objects.filter(otp = otp)
                if data:
                    username = ''
                    first_name = ''
                    last_name = ''
                    email = ''
                    password1 = ''
                    for i in data:
                        print(i.username)
                        username = i.username
                        first_name = i.first_name
                        last_name = i.last_name
                        email = i.email
                        password1 = i.password1

                    user = User.objects.create_user(username, email, password1)
                    user.first_name = first_name
                    user.last_name = last_name
                    user.save()
                    data.delete()
                    messages.success(request,'Account is created successfully!')
                    return HttpResponseRedirect('/verify/')   
                else:
                    messages.success(request,'Entered OTO is wrong')
                    return HttpResponseRedirect('/verify/')
        else:            
            form = VerifyForm()
        return render(request,'html/verify.html',{'form':form})
    else:
        return HttpResponseRedirect('/success/')


def success(request):
    if request.user.is_authenticated:
        # Vérifier si l'utilisateur est un médecin (exemple: groupe "Medecins")
        if request.user.groups.filter(name='Medecins').exists():
            return render(request, 'html/doctor_home.html')
        else:
            return render(request, 'html/patient_home.html')
    else:
        return HttpResponseRedirect('/')

# Dans vos views.py

def login_function(request):
    # Déconnexion forcée si déjà authentifié
    if request.user.is_authenticated:
        logout(request)
        return HttpResponseRedirect('/login/')
    
    if request.method == 'POST':
        form = LoginForm(request=request, data=request.POST)
        if form.is_valid():
            username = form.cleaned_data['username']
            password = form.cleaned_data['password']
            
            usr = authenticate(username=username, password=password)
            if usr is not None:
                # Nettoyage complet de la session
                request.session.flush()
                
                # Envoi OTP
                email = usr.email
                otp = sendEmail(email)
                
                # Stockage temporaire
                request.session['login_otp'] = otp
                request.session['otp_user_id'] = usr.id
                request.session.set_expiry(300)  # 5 minutes pour valider l'OTP
                
                return HttpResponseRedirect('/verify-login/')
            else:
                messages.error(request, "Identifiants incorrects")
    else:
        form = LoginForm()
    
    return render(request, 'html/login.html', {'form': form})

def verify_login(request):
    if 'otp_user_id' not in request.session:
        return redirect('login')
    
    if request.method == 'POST':
        entered_otp = request.POST.get('otp', '')
        saved_otp = request.session.get('login_otp', '')
        
        if entered_otp == saved_otp:
            user = User.objects.get(id=request.session['otp_user_id'])
            login(request, user)
            
            # Nettoyage de la session
            request.session.pop('login_otp', None)
            request.session.pop('otp_user_id', None)
            
            # Redirection basée sur le groupe
            if user.groups.filter(name='Medecins').exists():
                return redirect('medecin')
            return redirect('patient')
        else:
            messages.error(request, "Code OTP incorrect")
    
    return render(request, 'html/verify_login.html')
def logout_function(request):
    if request.user.is_authenticated:
        request.session.flush()
        logout(request)
    return HttpResponseRedirect('/login/')

    def patient_dashboard(request):
        if not request.user.is_authenticated:
            return HttpResponseRedirect('/login/')
        return render(request, 'html/patient_home.html')

from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required

@login_required
def patient_dashboard(request):
    """Tableau de bord spécifique pour les patients"""
    # Vérification supplémentaire si vous voulez forcer le rôle patient
    if request.user.groups.filter(name='Medecins').exists():
        return redirect('medecin')
    
    context = {
        'user': request.user,
        'is_patient': True
    }
    return render(request, 'html/patient_home.html', context)

@login_required
def medecin_dashboard(request):
    """Tableau de bord spécifique pour les médecins"""
    if not request.user.groups.filter(name='Medecins').exists():
        return redirect('patient')
    
    context = {
        'user': request.user,
        'is_doctor': True
    }
    return render(request, 'html/doctor_home.html', context)

# views.py
from django.contrib.auth import login
from .models import UserProfile

def patient_signup(request):
    if request.method == 'POST':
        form = PatientSignupForm(request.POST)
        if form.is_valid():
            user = form.save()
            UserProfile.objects.create(
                user=user,
                is_doctor=False,
                assurance_maladie=form.cleaned_data['assurance_maladie']
            )
            login(request, user)
            return redirect('patient_dashboard')
    else:
        form = PatientSignupForm()
    return render(request, 'registration/patient_signup.html', {'form': form})

# Accès restreint aux admins
from django.contrib.admin.views.decorators import staff_member_required

@staff_member_required
def doctor_signup(request):
    if request.method == 'POST':
        form = DoctorSignupForm(request.POST)
        if form.is_valid():
            user = form.save()
            UserProfile.objects.create(
                user=user,
                is_doctor=True,
                license_number=form.cleaned_data['license_number'],
                specialite=form.cleaned_data['specialite']
            )
            return redirect('admin:index')
    else:
        form = DoctorSignupForm()
    return render(request, 'admin/doctor_signup.html', {'form': form})