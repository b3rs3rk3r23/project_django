from django import forms
from django.contrib.auth.forms import UserCreationForm,AuthenticationForm,UsernameField
from django.contrib.auth.models import User
from django.core import validators
def validete_username(value):
    if len(value)<=2:
        raise forms.ValidationError(f"Your username cannot be of {len(value)}  word")

class CreateUser(UserCreationForm):
    password1 = forms.CharField(label="Password", widget = forms.PasswordInput(attrs={"placeholder":"Password",'autocomplete':'new-password','class':'form-control'}),error_messages={"required":"Please enter password"},)
    password2 = forms.CharField(label="Re-enter",widget= forms.PasswordInput(attrs={"placeholder":"Re-Enter",'autocomplete':'new-password','class':'form-control'}),help_text="Make sure your password contains 'small letter','capital letter','numbers' and 'symbols'",error_messages={"required":"Re-Enter password field cannot be empty"})
    username = forms.CharField(label="username",widget=forms.TextInput(attrs={"placeholder":"Username","id":"username",'class':'form-control'}),validators=[validete_username])
    first_name = forms.CharField(widget=forms.TextInput(attrs={"placeholder":"First Name","required":True,'class':'form-control'}),error_messages={"required":"First name cannot be empty"})
    last_name = forms.CharField(widget=forms.TextInput(attrs={"placeholder":"First Name","required":True,'class':'form-control'}),error_messages={"required":"Last name cannot be empty"})
    email = forms.CharField(widget=forms.EmailInput(attrs={"required":True,"Placeholder":"Email",'class':'form-control'}),error_messages={'required':'Email fields should not be empty'})
    class  Meta:
        model = User
        fields =['username','first_name','last_name','email','password1','password2']
    

class VerifyForm(forms.Form):
    otp = forms.CharField(label='OTP',max_length=70,widget=forms.TextInput(attrs={'class':'form-control','placeholder':'OTP','required':True}),error_messages={'required':'Enter a otp'})


class LoginForm(AuthenticationForm):
    username = UsernameField(widget=forms.TextInput(attrs={"placeholder":"Username","class":"form-control"}))
    password = forms.CharField(widget=forms.PasswordInput(attrs={"placeholder":"password",'autocomplete':'current-password',"class":"form-control"}))  

# forms.py
from django import forms
from django.contrib.auth.forms import UserCreationForm
from django.contrib.auth.models import User

# Liste des spécialités médicales (à adapter selon vos besoins)
SPECIALITES = [
    ('cardiologie', 'Cardiologie'),
    ('dermatologie', 'Dermatologie'),
    ('pediatrie', 'Pédiatrie'),
    ('generaliste', 'Médecine Générale'),
    # Ajoutez d'autres spécialités au besoin
]

class PatientSignupForm(UserCreationForm):
    """
    Formulaire d'inscription spécifique pour les patients
    Hérite de UserCreationForm pour gérer la création de compte utilisateur
    """
    assurance_maladie = forms.CharField(
        max_length=20,
        label="Numéro d'assurance maladie",
        help_text="Votre numéro de sécurité sociale",
        widget=forms.TextInput(attrs={'class': 'form-control'})
    )
    
    class Meta(UserCreationForm.Meta):
        model = User
        fields = ('username', 'email', 'first_name', 'last_name', 'password1', 'password2')
        
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Personnalisation des champs existants
        self.fields['username'].widget.attrs.update({'class': 'form-control'})
        self.fields['email'].widget.attrs.update({'class': 'form-control'})
        self.fields['first_name'].widget.attrs.update({'class': 'form-control'})
        self.fields['last_name'].widget.attrs.update({'class': 'form-control'})
        self.fields['password1'].widget.attrs.update({'class': 'form-control'})
        self.fields['password2'].widget.attrs.update({'class': 'form-control'})

class DoctorSignupForm(UserCreationForm):
    """
    Formulaire d'inscription spécifique pour les médecins
    Nécessite des informations professionnelles supplémentaires
    """
    license_number = forms.CharField(
        max_length=20,
        label="Numéro de licence médicale",
        widget=forms.TextInput(attrs={'class': 'form-control'})
    )
    specialite = forms.ChoiceField(
        choices=SPECIALITES,
        label="Spécialité médicale",
        widget=forms.Select(attrs={'class': 'form-control'})
    )
    
    class Meta(UserCreationForm.Meta):
        model = User
        fields = ('username', 'email', 'first_name', 'last_name', 'password1', 'password2')
        
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Personnalisation des champs existants
        self.fields['username'].widget.attrs.update({'class': 'form-control'})
        self.fields['email'].widget.attrs.update({'class': 'form-control'})
        self.fields['first_name'].widget.attrs.update({'class': 'form-control'})
        self.fields['last_name'].widget.attrs.update({'class': 'form-control'})
        self.fields['password1'].widget.attrs.update({'class': 'form-control'})
        self.fields['password2'].widget.attrs.update({'class': 'form-control'})

class DoctorVerificationForm(forms.Form):
    """
    Formulaire optionnel pour la vérification des documents médicaux
    """
    license_file = forms.FileField(
        label="Copie de la licence médicale",
        help_text="Téléversez un scan de votre licence au format PDF ou JPG"
    )
    diploma = forms.FileField(
        label="Copie du diplôme",
        help_text="Téléversez un scan de votre diplôme médical"
    )