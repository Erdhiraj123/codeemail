"""
Create Views for Account application.
"""
import logging
import json
import re
from django.shortcuts import render, get_object_or_404

from django.db.models import Q
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render, redirect
from django.contrib.auth import authenticate, login
from django.contrib import messages
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.contrib.auth import logout
from django.core.mail import send_mail
from django.http import JsonResponse, HttpResponse
from .messages import (VALID_CREDENTIAL, LOGIN_SUCCESSFULL, ERROR_MESSAGE, REGISTER_SUCCESSFULL,
                       REGISTRATION_SUCCESS_EMAIL, APPROVE_REGISTERED_USER, APPROVE_REGISTERED_USER_SUBJECT,
                       REGISTRATION_SUCCESS_EMAIL_SUBJECT, DECLINE_REGISTERED_USER_SUBJECT, DECLINE_REGISTERED_USER,
                       FORGET_PASSWORD_SUBJECT, FORGET_PASSWORD_MESSAGE, PASSWORD_RESET_MESSAGE, PASSWORD_RESET_SUBJECT,
                       NOT_VALID_USER, NOT_ACTIVE_USER, PASSWORD_UPDATE, USER_CREATED_SUCCESSFULLY,
                       AGENCY_USER_CREATED_SUBJECT, AGENCY_USER_CREATED_MESSAGE,SIGNUP_USER_MESSAGE,SIGNUP_USER_SUBJECT)
from .models import User, UserProfile, Department, Rank
from .forms import (UserForm, UserProfileForm, LoginForm, SetPasswordForm, DepartmentForm, RankForm, ForgetPasswordForm,
                    PasswordChangeForm, ManageUserForm, ManageUserProfileForm, UpdateUserForm,
                    UpdateUserProfileForm)

logger = logging.getLogger(__name__)


def signup(request):
    # if request.user.is_superuser:
    #     department=Department.objects.all()
    # else:
    #     department=Department.objects.filter(created_by=request.user)
    #     print(department)


    if request.method == 'POST':
        email = request.POST.getlist('additional_email')
        department_name = request.POST.get('selected_department')
        
        user=User(email=email)
        uid = urlsafe_base64_encode(force_bytes(user.id))
        token = default_token_generator.make_token(user)
        subject = SIGNUP_USER_SUBJECT
        message = SIGNUP_USER_MESSAGE.format(department_name=department_name)
        from_email = settings.EMAIL_HOST_USER

        for email in email:
            recipient_list = [email,department_name]
            send_mail(subject, message, from_email, recipient_list)

        return HttpResponse("email send done")

    return render(request, 'account/signup_form.html',{'department':department})



def register_external_user_view(request):
    """
        Save the external user details into the database, send email after registration
    """
    if request.method == 'POST':
        try:
            user_form = UserForm(request.POST)
            user_profile_form = UserProfileForm(request.POST, request.FILES)
            print(user_form.is_valid(), user_profile_form.is_valid())
            if user_form.is_valid() and user_profile_form.is_valid():
                email = user_form.cleaned_data.get('email')
                first_name = user_form.cleaned_data.get('first_name')
                last_name = user_form.cleaned_data.get('last_name')
                new_user = User.objects.create(username=email, email=email, first_name=first_name, last_name=last_name,
                                               is_active=False)
                new_user.save()
                user_profile = user_profile_form.save(commit=False)
                user_profile.user = new_user
                user_profile.save()
                send_mail(
                    REGISTRATION_SUCCESS_EMAIL_SUBJECT,
                    REGISTRATION_SUCCESS_EMAIL.format(new_user.first_name + ' ' + new_user.last_name),
                    settings.EMAIL_HOST_USER,
                    [new_user.email],
                    fail_silently=False,
                )
                messages.success(request, REGISTER_SUCCESSFULL)
                return redirect('login')
        except Exception as e:
            return redirect('register_external_user')
    else:
        user_form = UserForm()
        user_profile_form = UserProfileForm()
    return render(request, 'account/signup.html', {'user_form': user_form, 'user_profile_form': user_profile_form})


def login_view(request):
    """
          Login user view to let the user access the application
    """
    if request.method == 'POST':
        try:
            login_form = LoginForm(request.POST)
            if login_form.is_valid():
                email = login_form.cleaned_data.get('email')
                password = login_form.cleaned_data.get('password')
                user = authenticate(email=email, password=password)
                if user is not None:
                    messages.success(request, LOGIN_SUCCESSFULL)
                    login(request, user)
                    return redirect('home')
                else:
                    messages.error(request, VALID_CREDENTIAL)
                    return redirect('login')
        except Exception as exc:
            logger.error(exc)
            messages.error(request, ERROR_MESSAGE)
            return redirect('login')
    else:
        login_form = LoginForm()
    return render(request, 'account/login.html', {'login_form': login_form})


@login_required
def logout_view(request):
    """
         Logout view to let the user out of the application
    """
    try:
        logout(request)
        return redirect('login')
    except Exception as exc:
        logger.error(exc)
        messages.error(request, ERROR_MESSAGE)
        return redirect('home')


@login_required
def home_view(request):
    """
           Redirect user to the Dashboard screen
    """
    try:
        user = User.objects.get(email=request.user.email)
        user_profile = UserProfile.objects.filter(user=user).first()
        return render(request, 'account/home.html', {'user_profile': user_profile})
    except Exception as exc:
        logger.error(exc)
        messages.error(request, ERROR_MESSAGE)
        return redirect('home')


def set_password_view(request, pk):
    """
             Set the User password to access the application
    """
    user = User.objects.get(id=pk)
    if request.method == 'POST':
        try:
            form = SetPasswordForm(request.POST)
            if form.is_valid():
                password = form.cleaned_data.get('new_password2')
                user.set_password(password)
                user.save()
                messages.success(request, "Password Set Successfully")
                return redirect('login')
            return render(request, 'account/set_password.html', {'form': form, 'user': user})
        except Exception as exc:
            logger.error(exc)
            messages.error(request, ERROR_MESSAGE)
            return redirect('login')
    else:
        form = SetPasswordForm()
    return render(request, 'account/set_password.html', {'form': form, 'user': user})


def forget_password_view(request):
    """
            Send user an email after email verification to reset their password
    """
    if request.method == 'POST':
        try:
            form = ForgetPasswordForm(request.POST)
            
            if form.is_valid():
          
                email = form.cleaned_data['email']
                user = User.objects.filter(email=email).first()
           
                if user:
                    if user.is_active:
                        uid = urlsafe_base64_encode(force_bytes(user.id))
                        token = default_token_generator.make_token(user)
                        subject = FORGET_PASSWORD_SUBJECT
                        message = FORGET_PASSWORD_MESSAGE.format(uid, token)
                        email_from = settings.EMAIL_HOST_USER
                        recipient_list = [email, ]
                        send_mail(subject, message, email_from, recipient_list)
                        return render(request, 'account/email_send_user.html', {'email': email})
                    print("inactive user")
                    messages.error(request, NOT_ACTIVE_USER)
                    return redirect('forget_password')
                messages.error(request, NOT_VALID_USER)
                return redirect('forget_password')
        except Exception as exc:
            logger.error(exc)
            messages.error(request, ERROR_MESSAGE)
            return redirect('forget_password')
    form = ForgetPasswordForm()
    return render(request, 'account/forgot_password.html', {'form': form})


def reset_password_view(request, uidb64, token):
    """
            Reset the user password and saved into database
    """

    if request.method == 'POST':
        try:
            form = SetPasswordForm(request.POST)
            if form.is_valid():
                uid = urlsafe_base64_decode(uidb64)
                user = User.objects.filter(id=uid).first()
                subject = PASSWORD_RESET_SUBJECT
                message = PASSWORD_RESET_MESSAGE
                email_from = settings.EMAIL_HOST_USER
                recipient_list = [user.email, ]
                new_password = form.cleaned_data['new_password2']
                user.set_password(new_password)
                user.save()
                send_mail(subject, message, email_from, recipient_list)
                return render(request, 'account/password_reset_successfully.html')
            return render(request, 'account/reset_password.html', {'form': form, 'uidb64': uidb64, 'token': token})
        except Exception as exc:
            logger.error(exc)
            messages.error(request, ERROR_MESSAGE)
            return redirect('reset_password')
    form = SetPasswordForm()
    uid = urlsafe_base64_decode(uidb64)
    user = User.objects.filter(pk=uid).first()
    if user and default_token_generator.check_token(user, token):
        return render(request, 'account/reset_password.html', {'form': form, 'uidb64': uidb64, 'token': token})
    return redirect("login")


@login_required
def change_password_view(request):
    """
                Change Password to change the password of login user

    """
    if request.method == 'POST':
        try:
            form = PasswordChangeForm(request.user, request.POST)
            if form.is_valid():
                u = User.objects.get(email=request.user.email)
                u.set_password(form['password1'].value())
                u.save()
                messages.success(request, PASSWORD_UPDATE)
                return redirect("login")
            return render(request, 'account/change_password.html', {'form': form})
        except Exception as exc:
            logging.error(exc)
            messages.success(request, ERROR_MESSAGE)
            return redirect('change_password')
    form = PasswordChangeForm(request.user)
    return render(request, 'account/change_password.html', {'form': form})


@login_required
def update_profile_view(request):
    """
       User can Update their Profile

    """
    user = User.objects.get(email=request.user.email)
    userprofile = UserProfile.objects.filter(user=user).first()
    if request.method == 'POST':
        try:
            updated_request = request.POST.copy()
            updated_request.update({'email': user.email})
            user_form = UpdateUserForm(updated_request, instance=request.user)
            if not request.user.is_superuser:
                updated_request.update({'rank': userprofile.rank})
                user_profile_form = UpdateUserProfileForm(updated_request, request.FILES, instance=userprofile)
                if user_form.is_valid() and user_profile_form.is_valid():
                    user_form.save()
                    user_profile_form.save()
                    messages.success(request, 'Your profile is updated successfully')
                    return redirect('update_profile')
                return render(request, 'account/update_profile.html',
                              {'user_form': user_form, 'user_profile_form': user_profile_form})
            else:
                user_form.save()
                messages.success(request, 'Your profile is updated successfully')
                return redirect('update_profile')
        except Exception as exc:
            logging.error(exc)
            messages.success(request, ERROR_MESSAGE)
            return redirect('change_password')
    user_form = UpdateUserForm(instance=request.user)
    if not request.user.is_superuser:
        user_profile_form = UpdateUserProfileForm(instance=userprofile)
        return render(request, 'account/update_profile.html',
                      {'user_form': user_form, 'user_profile_form': user_profile_form})
    else:
        return render(request, 'account/update_profile.html',
                      {'user_form': user_form})


@login_required
def manage_registration_view(request):
    """
          Manage the external user verification
    """
    try:
        all_users = UserProfile.objects.filter(user__is_superuser=False, user__is_staff=False)
        return render(request, 'account/manage_registration.html', {'all_users': all_users})
    except Exception as exc:
        logger.error(exc)
        messages.error(request, ERROR_MESSAGE)
        return redirect('home')


@login_required
def approve_user_view(request):
    """
            Approve/Declined the user to access the application
    """
    if request.method == 'POST':
        try:
            button_id = request.POST.get('button_val')
            user = UserProfile.objects.get(id=int(button_id[:-1]))

            if button_id[-1] == 'A':
                user.is_verified = "approve"
                user.user.is_active = True
                user.user.save()
                user.save()
                send_mail(
                    APPROVE_REGISTERED_USER_SUBJECT,
                    APPROVE_REGISTERED_USER.format(user.user.first_name + ' ' + user.user.last_name,
                                                   f'{request.META["wsgi.url_scheme"]}://{request.META["HTTP_HOST"]}/setpassword/{user.user.id}'),
                    settings.EMAIL_HOST_USER,
                    [user.user.email],
                    fail_silently=False,
                )
            else:
                user.is_verified = "decline"
                user.save()
                send_mail(
                    DECLINE_REGISTERED_USER_SUBJECT,
                    DECLINE_REGISTERED_USER.format(user.user.first_name + ' ' + user.user.last_name),
                    settings.EMAIL_HOST_USER,
                    [user.user.email],
                    fail_silently=False,
                )
            return redirect('manage_registration')
        except Exception as exc:
            logger.error(exc)
            messages.error(request, ERROR_MESSAGE)
            return redirect('manage_registration')


@login_required
def manage_agency_user_view(request):
    """
              Manage the Agency users
    """
    if request.method == 'POST':
        try:
            user_form = ManageUserForm(request.POST)
            user_profile_form = ManageUserProfileForm(request.POST)
            if user_form.is_valid() and user_profile_form.is_valid():
                email = user_form.cleaned_data.get('email')
                first_name = user_form.cleaned_data.get('first_name')
                last_name = user_form.cleaned_data.get('last_name')
                new_user = User.objects.create(username=email, email=email, first_name=first_name, last_name=last_name,
                                               is_active=True, is_staff=True)
                new_user.save()
                user_profile = user_profile_form.save(commit=False)
                user_profile.user = new_user
                user_profile.save()
                send_mail(
                    AGENCY_USER_CREATED_SUBJECT, 
                    AGENCY_USER_CREATED_MESSAGE.format(new_user.first_name + ' ' + new_user.last_name, user_profile.department.name,
                                                   f'{request.META["wsgi.url_scheme"]}://{request.META["HTTP_HOST"]}/setpassword/{new_user.id}'),
                    settings.EMAIL_HOST_USER,
                    [new_user.email],
                    fail_silently=False,
                )
                messages.success(request, USER_CREATED_SUCCESSFULLY)
                return redirect('manage_agency_user')
        except Exception as exc:
            logger.error(exc)
            messages.error(request, ERROR_MESSAGE)
            return redirect('manage_agency_user')
    user_form = ManageUserForm()
    user_profile_form = ManageUserProfileForm()
    all_user = UserProfile.objects.all()
    return render(request, 'account/manage_agency_user.html',
                      {'user_form': user_form, 'user_profile_form': user_profile_form, 'all_user': all_user})

@login_required
def manage_department_view(request):
    """
        Add the new department and show listing of existing department  
    """
    if request.method == 'POST':
        try:
            user_form = DepartmentForm(request.POST)
            if user_form.is_valid():
                obj = user_form.save(commit=False)
                obj.created_by = request.user
                obj.save()
                messages.success(request, "Department Created Successfully")
        except Exception as exc:
            logger.error(exc)
            messages.error(request, ERROR_MESSAGE)
            return redirect('manage_department')
    all_departments = Department.objects.filter(status = True)
    states = Department.state.field.choices
    return render(request, 'account/manage_department.html',
                  { 'all_departments': all_departments , "states": states})

@login_required
def manage_rank_view(request):
    """
               Add the new Ranks and show listing of existing Ranks with department details
    """

    if request.method == 'POST':
        try:
            
            department = request.POST.get("department")
            rank = request.POST.get("rank")
            department = Department.objects.get(name=department)
            created_by = User.objects.get(email=request.user)

            obj = Rank(name = rank , department = department , created_by= created_by)
            obj.save()
        except Exception as exc:
            logger.error(exc)
            messages.error(request, ERROR_MESSAGE)
            return redirect('manage_rank')
   
    all_ranks = Rank.objects.filter(status=True)
    all_departments = Department.objects.values_list("name")
    return render(request, 'account/manage_rank.html',{'all_ranks': all_ranks, "departments":all_departments})

@login_required
def dep_rank_view(request):
    if request.method == 'POST':
        dep = Department.objects.get(name=request.POST.get('selected_val'))
        rank_objs = Rank.objects.filter(department=dep)
        d = []
        for obj in rank_objs:
            d += [obj.name]
        return JsonResponse({'ranks': d})


# riys add functions 19 Dec
def view_details(request, id):
    if request.method == "POST":
        pi = Department.objects.get(pk=id)
        form = DepartmentForm(request.POST, instance=pi)
        if form.is_valid():
            form.save()
            return redirect('modal')
    else:
        pi = Department.objects.get(pk=id)
        form = DepartmentForm(instance=pi)
    return render(request, 'account/viewdetails.html', {"form": form})

@login_required
def updatedepartment(request):
    if request.method == 'POST':
        department_id = request.POST.get("item_id")
        department_name = request.POST.get('department_name')
        department = Department.objects.get(id=department_id)

        # Check if the department name already exists excluding the current department
        existing_department = Department.objects.filter(
            Q(name__iexact=department_name)
        ).exclude(id=department_id)

        if existing_department.exists():
            return JsonResponse({'exists': True, 'message': 'Department with this name already exists, please choose another name'})
        else:
            # Update other fields and save the department
            department.name = department_name  # Set the name separately
            department.address = request.POST.get('address')
            department.state = request.POST.get('state')  # Make sure state is set
            department.city = request.POST.get('city')
            department.zip = request.POST.get('zip')
            department.phone = request.POST.get('phone')
            department.agency_executive = request.POST.get('agency_executive')
            department.city_size = request.POST.get('city_size')
            department.department_size = request.POST.get('department_size')

            department.save()
            print(request.POST.get('city'))
            return redirect("/managedepartment")


def check_duplicateUpdate_view(request):
    if request.method == 'POST':
        department_id = request.POST.get("item_id")
        department_name = request.POST.get('department_name')
        department = Department.objects.get(id=department_id)

        # Check if the department name already exists excluding the current department
        existing_department = Department.objects.filter(
            Q(name__iexact=department_name)
        ).exclude(id=department_id)

        if existing_department.exists():
            return JsonResponse(
                {'exists': True, 'message': 'Department with this name already exists, please choose another name'}
            )
        return JsonResponse({"exists": False})



def check_duplicateDepartment_view(request):
    if request.method == 'POST':
        name = request.POST.get('department_name')
        if Department.objects.filter(name=name).exists():
            return JsonResponse({'exists': True, 'message': 'Department name already exists'})
        return JsonResponse({"exists": False})

@login_required
def adddepartment(request):
    if request.method == 'POST':
        print("You are in add departmnet")
        name = request.POST.get('department_name')

        address = request.POST.get('address')
        state = request.POST.get('state')
        city = request.POST.get('city')
        zip = request.POST.get('zip')
        phone = request.POST.get('phone')
        agency_executive = request.POST.get('agency_executive')
        city_size = request.POST.get('city_size')
        department_size = request.POST.get('department_size')
        image = request.FILES.get('logo')
        #
        # if any(char.isdigit() for char in name) or any(char in "!@#$%" for char in name):
        #     return redirect("/managedepartment")
        #
        # if not re.match("^[a-zA-Z0-9\s,'-]+$", address):
        #     return redirect("/managedepartment")
        #
        # if len(str(zip)) != 6:
        #     return redirect("/managedepartment")
        #
        # if not agency_executive.isdigit():
        #     return redirect("/managedepartment")
        #
        # if any(char.isdigit() for char in city) or any(char in "!@#$%" for char in city):
        #     return redirect("/managedepartment")
        #
        # if not city_size.isdigit():
        #     return redirect("/managedepartment")
        #
        # # Validation for department_size
        # if not department_size.isdigit():
        #     return redirect("/managedepartment")
        #
        # us_phone_pattern = r'^(?:\+1\s?)?(?:\(\d{3}\)\s?\d{3}-\d{4}|\d{3}-\d{3}-\d{4})$'
        #
        # if not re.match(us_phone_pattern, phone):
        #     return redirect("/managedepartment")


        department = Department(
            name=name,
            address=address,
            state=state,
            city=city,
            zip=zip,
            phone=phone,
            agency_executive=agency_executive,
            city_size=city_size,
            department_size=department_size,
            created_by=request.user,
            department_logo=image  # Set the image field here
        )
        department.save()
        print(request.POST.get('city'))
        return redirect("/managedepartment")



@login_required
def deletedepartment(request, id):
    obj = Department.objects.get(id=id)
    obj.status = False
    obj.save()
    return redirect("/managedepartment")

@login_required
def getDepartmentData_view(request , id):
    try:
        department = Department.objects.filter(id=id).values()
        data={
            'department_id' : department[0]['id'],
            'department_name': department[0]['name'],
            'address': department[0]['address'],
            'state': department[0]['state'],
            'city': department[0]['city'],
            'zip': department[0]['zip'],
            'phone': department[0]['phone'],
            'agency_executive': department[0]['agency_executive'],
            'city_size': department[0]['city_size'],
            'department_size': department[0]['department_size'],
            'department_logo': department[0]['department_logo']
        }
        return JsonResponse(data)
    except Department.DoesNotExist:
        print("You are in trouble")
        return JsonResponse({'error': 'Department not found'}, status=404) 


@csrf_exempt
def filter_department_view(request):

    if request.method == 'POST':
        received_data = json.loads(request.body)   
        all_departments = Department.objects.filter(status = True).values() 
        states = Department.state.field.choices
        department_id =[] 
        for department in all_departments:
            flag = False
            if(received_data['filter_data'][0] != "Select Department"):
                if received_data['filter_data'][0] == department['name']:
                    flag = True
                else:
                    continue
            
            if(received_data['filter_data'][1] != "Select City"):
                if received_data['filter_data'][1] == department['city']:
                    flag = True
                else:
                    continue
            if(received_data['filter_data'][2] != "Select State"):
                if received_data['filter_data'][2] == department['state']:
                    flag = True
                else:
                    continue    
            if(flag == True):
                department_id.append(department['id'])

        
        
        all_departments = Department.objects.filter(status = True , id__in = department_id).values() 
        departments_data = [department for department in all_departments]
        
        # Process the list as needed
        # For demonstration, simply echoing the received list
        return JsonResponse({'received_list': departments_data})
        
    else:
        return JsonResponse({'error': 'Invalid request method'})

#rank
# Return data for edit rank form 
def editRank_view(reuqest , id):
    try:
        rank_data = Rank.objects.filter(id=id)[0]
        data = {
            "rank_id" : rank_data.id,
            "department_name" : rank_data.department.name,
            "rank_name": rank_data.name,
        }

        return JsonResponse(data)
    
    except Rank.DoesNotExist:
        print("Rank does not exists ")
        return JsonResponse({"error":"Rank doest not found on your requested id"}, status=404)

def deleterank_view(request, id):
    obj = Rank.objects.get(id=id)
    obj.status = False
    obj.save()
    return redirect("/managerank")

def updaterank_view(request):
    if request.method == "POST":
        obj = Rank.objects.get(id= request.POST.get("item_id"))
        obj.name = request.POST.get("rank_name")
        obj.department = Department.objects.get(name=request.POST.get("department_name"))
        obj.save()
    return redirect("/managerank")

def filterrank_view(request):
    if request.method == "POST":
        rank = json.loads(request.body)['filter_data'][0]
        department = json.loads(request.body)['filter_data'][1]
        data = []
        if(department != "Select department"):
            if(rank !=""):
                data = Rank.objects.filter(status = True, name=rank , department = Department.objects.get(name=department).id)
            else:
                data = Rank.objects.filter(status = True, department = Department.objects.get(name=department).id)
        elif(rank != ""):
            data = Rank.objects.filter(status = True, name = rank)

        data = [{"id":rank.id , "name":rank.name , "department": rank.department.name} for rank in data ]
        return JsonResponse({"received_list":data})
    else:
        return JsonResponse({"error":"Invalid request found"})




def getrank(request, department_id):
    try:
        department = get_object_or_404(Department, id=department_id)
        ranks = Rank.objects.filter(department=department)

        if ranks.exists():
            ranks_data = list(ranks.values())
            print(ranks_data)
            return JsonResponse({'ranks_data': ranks_data})
        else:
            return JsonResponse({'error': f'No ranks found for the specified department ID: {department_id}'}, status=404)

    except Exception as e:
        return JsonResponse({'error': str(e)}, status=500)