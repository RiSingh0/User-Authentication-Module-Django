# Create your views here.
from django.contrib import messages
from django.contrib.auth import update_session_auth_hash
from django.contrib.auth.forms import PasswordChangeForm
from django.shortcuts import render, redirect
from django.shortcuts import render
from dappx.forms import UserForm,UserProfileInfoForm,EditUserForm,EditUserProfileInfoForm
from django.contrib.auth import authenticate, login, logout
from django.http import HttpResponseRedirect, HttpResponse
from django.urls import reverse
from django.contrib.auth.decorators import login_required
from google.oauth2 import id_token
from google.auth.transport import requests
from .models import UserProfileInfo
import json
import requests as Caprequests
from django.contrib.auth.models import User
from django.utils.encoding import force_bytes, force_text
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template.loader import render_to_string
from .tokens import account_activation_token
from django.core.mail import EmailMessage
from django.contrib.sites.shortcuts import get_current_site

#from django.views.decorators.csrf import csrf_exempt

def index(request):
    return render(request,'dappx/index.html')
@login_required
def special(request):
    return HttpResponse("You are logged in !")
@login_required
def user_logout(request):
    logout(request)
    return HttpResponseRedirect(reverse('index'))

def register(request):
    if request.user.is_authenticated:
        return HttpResponseRedirect(reverse('index'))
    else:
        args = {}
        if request.method == 'POST':
            #Recaptha stuff
            ClientKey = request.POST.get('g-recaptcha-response')
            SecretKey=''

            CapthchaData = {
                'secret' : SecretKey,
                'response' : ClientKey
            }
            r = Caprequests.post('https://www.google.com/recaptcha/api/siteverify', data=CapthchaData)
            response=json.loads(r.text)
            verify=response['success']
            if verify:
                user_form = UserForm(data=request.POST)
                profile_form = UserProfileInfoForm(data=request.POST)
                if user_form.is_valid() and profile_form.is_valid():
                    user=user_form.save(commit=False)
                    user.is_active = False
                    user.save()
                    profile=profile_form.save(commit=False)
                    profile.user=user
                    if 'profile_pic' in request.FILES:
                        print('found it')
                        profile.profile_pic = request.FILES['profile_pic']
                        profile.save()
                    # profile.profile_pic = "/media/" + str(profile.profile_pic)
                    # profile.save()
                    current_site = get_current_site(request)
                    mail_subject = 'Activate your Account.'
                    message = render_to_string('dappx/acc_active_email.html', {
                        'user': user,
                        'domain': current_site.domain,
                        'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                        'token': account_activation_token.make_token(user),
                    })
                    to_email = user_form.cleaned_data.get('email')
                    email = EmailMessage(
                        mail_subject, message, to=[to_email]
                    )
                    email.send()
                    messages.success(request, 'Please confirm your email address to complete the registration, We have send the Email confirmation link to your Email.')
                    # username = user_form.cleaned_data.get('username')
                    # raw_password = user_form.cleaned_data.get('password1')
                    # user = authenticate(username=username, password=raw_password)
                    # login(request, user)
                    return HttpResponseRedirect(reverse('index'))
                else:
                    print('nothing')
            else:
                user_form = UserForm()
                profile_form = UserProfileInfoForm()
                messages.warning(request, 'fill the reCAPTCHA')
        else:
            user_form = UserForm()
            profile_form = UserProfileInfoForm()
        args['user_form'] = user_form
        args['profile_form'] = profile_form
        return render(request, 'dappx/registration.html', args)
def user_login(request):
    if request.user.is_authenticated:
        return HttpResponseRedirect(reverse('index'))
    else:
        if request.method == 'POST':
            username = request.POST.get('username')
            password = request.POST.get('password')
            user = authenticate(username=username, password=password)
            if user:
                if user.is_active:
                    login(request,user)
                    return HttpResponseRedirect(reverse('index'))
                else:
                    return HttpResponse("Your account was inactive.")
            else:
                messages.warning(request, 'Invalid Username or Password')

    return render(request, 'dappx/login.html', {})

def google_login(request):
    token = request.POST.get('id_token')
    name = request.POST.get('name')
    image = request.POST.get('image')
    email = request.POST.get('email')
    first_name = request.POST.get('firstname')
    last_name = request.POST.get('lastname')
    print('token:',token)
    print('name:', name)
    print('image:', image)
    print('email:', email)
    print('first_name:', first_name)
    print('last_name:', last_name)
    try:
        CLIENT_ID='222571355972-iqurv219kufrepa3uqjlqoumqg62ke2r.apps.googleusercontent.com'
        idinfo = id_token.verify_oauth2_token(token, requests.Request(), CLIENT_ID)

        if idinfo['iss'] not in ['accounts.google.com', 'https://accounts.google.com']:
            raise ValueError('Wrong issuer.')

        userid = idinfo['sub']
        user = User.objects.all().filter(email=email, username=name)
        print(userid)
        if user:
            user = User.objects.all().get(email=email, username=name)
            login(request, user)
            return HttpResponseRedirect(reverse('index'))
        else:
            new_user = User(username=name, email=email, first_name=first_name, last_name=last_name)
            new_user.save()
            new_user_p = UserProfileInfo(user=new_user, google_id=userid, profile_pic=image)
            new_user_p.save()
            user = User.objects.all().filter(email=email, username=name)
            if user:
                user = User.objects.all().get(email=email, username=name)
                login(request, user)
                return HttpResponseRedirect(reverse('index'))
    except ValueError:

        pass
    return HttpResponse('token')

@login_required
def password(request):
        if request.method == 'POST':
            form = PasswordChangeForm(request.user, request.POST)
            if form.is_valid():
                user = form.save()
                update_session_auth_hash(request, user)  # Important!
                messages.success(request, 'Your password was successfully updated!')
                return redirect('password')
            else:
                messages.error(request, 'Please correct the error below.')
        else:
            form = PasswordChangeForm(request.user)
        return render(request, 'dappx/password.html', {
            'form': form
        })


def my_password_reset_view(request):
    return password_reset(request,
        template_name = 'dappx/registration/password_reset_form.html',
        email_template_name = 'dappx/registration/password_reset_email.html',
        subject_template_name ='changeMe',
        post_reset_redirect = reverse('adminApp:admin_password_reset_done'),
        password_reset_form = MyPasswordResetForm, )

@login_required
def profile(request):
    if request.method == 'POST':
        user_form = EditUserForm(request.POST, instance=request.user)
        profile_form = EditUserProfileInfoForm(request.POST, instance=request.user.userprofileinfo)

        if user_form.is_valid() and profile_form.is_valid():
            user_form.save()
            profile=profile_form.save()
            if 'profile_pic' in request.FILES:
                profile.profile_pic = request.FILES['profile_pic']
                profile.save()
                # profile.profile_pic = "/media/" + str(profile.profile_pic)
                # profile.save()
            messages.success(request, 'Your profile was successfully updated!')
            return redirect('dappx:profile')
    else:
        user_form = EditUserForm(instance=request.user)
        profile_form =EditUserProfileInfoForm(instance=request.user.userprofileinfo)
        return render(request, 'dappx/profile.html',
              {'user_form': user_form,
               'profile_form': profile_form})

def activate(request, uidb64, token):
    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = True
        user.save()
        login(request, user)
        # return redirect('home')
        messages.success(request, 'Thank you for your email confirmation.')
        return HttpResponseRedirect(reverse('index'))
    else:
        return HttpResponse('Activation link is invalid!')

def delete_account(request):
    if request.method == 'POST':
        print(request.POST.get('email'))
        if request.user.email == request.POST.get('email'):
            current_site = get_current_site(request)
            mail_subject = 'Deactivate your Account.'
            message = render_to_string('dappx/acc_deactive_email.html', {
                'user': request.user,
                'domain': current_site.domain,
                'uid': urlsafe_base64_encode(force_bytes(request.user.pk)),
                'token': account_activation_token.make_token(request.user),
            })
            to_email = request.user.email
            email = EmailMessage(
                mail_subject, message, to=[to_email]
            )
            email.send()
            messages.success(request,'Please confirm your email address to complete the deactivation, We have send the Email confirmation link to your Email.')
            return HttpResponseRedirect(reverse('index'))
        else:
            messages.info(request,'Entered email is invalid!.')
            return HttpResponseRedirect(reverse('index'))

    else:
        return render(request, 'dappx/delete_account.html')


def deactivate(request, uidb64, token):
    try:
        uid = force_text(urlsafe_base64_decode(uidb64))
        user = User.objects.get(pk=uid)
    except(TypeError, ValueError, OverflowError, User.DoesNotExist):
        user = None
    if user is not None and account_activation_token.check_token(user, token):
        user.is_active = False
        user.save()
        logout(request)
        # return redirect('home')
        messages.success(request, 'Your account is successfully deactivated.')
        return HttpResponseRedirect(reverse('index'))
    else:
        return HttpResponse('Activation link is invalid!')
