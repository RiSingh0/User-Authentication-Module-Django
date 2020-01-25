from django import forms
from dappx.models import UserProfileInfo
from django.contrib.auth.models import User
from django.contrib.auth.forms import UserCreationForm, UserChangeForm

class UserForm(UserCreationForm):
    first_name = forms.CharField(
        max_length=30, required=True, help_text='Given Name.')
    last_name = forms.CharField(
        max_length=30, required=True, help_text='Family Name.')
    email = forms.EmailField(
        max_length=254, help_text='Required. Inform a valid email address.')

    class Meta:
        model = User
        fields = ('username', 'first_name', 'last_name',
                  'email', 'password1', 'password2', )

    def clean(self):
        # Get the email
        email = self.cleaned_data['email']
        if User.objects.filter(username=self.cleaned_data['username']).exists():
            raise forms.ValidationError(
                'This username address is already in use.')
        # Check to see if any users already exist with this email as a username.
        if User.objects.filter(email=self.cleaned_data['email']).exists():
            raise forms.ValidationError(
                'This email address is already in use.')


class UserProfileInfoForm(forms.ModelForm):
    YESNO_CHOICES = (('Male', 'Male'), ('Female', 'Female'), ('Others', 'Others'))
    Gender = forms.ChoiceField(choices=YESNO_CHOICES)
    class Meta():
        model = UserProfileInfo
        fields = ('Gender',)

    def __init__(self, *args, **kwargs):
        super(UserProfileInfoForm, self).__init__(*args, **kwargs)
        self.fields['Gender'].required = True


class EditUserForm(UserChangeForm):
    password = None

    class Meta:
        model = User
        fields = ('first_name', 'last_name',)


class EditUserProfileInfoForm(UserChangeForm):
    YESNO_CHOICES = (('male', 'male'), ('female', 'female'))
    Gender = forms.ChoiceField(choices=YESNO_CHOICES)
    password = None

    class Meta():
        model = UserProfileInfo
        fields = ('Gender',)

    def __init__(self, *args, **kwargs):
        super(EditUserProfileInfoForm, self).__init__(*args, **kwargs)
        self.fields['Gender'].required = False

        
# class UpdateProfile()
        # def clean(self):
    #     cleaned_data = super(UserForm, self).clean()
    #     password = cleaned_data.get("password")
    #     confirm_password = cleaned_data.get("confirm_password")

    #     if password != confirm_password:
    #         raise forms.ValidationError(
    #             "password and confirm_password does not match"
    #         )
