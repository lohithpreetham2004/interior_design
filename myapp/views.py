from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib import messages


# Create your views here.
def home(request):
    return render(request, "index.html")


def loginpage(request):
    if request.user.is_authenticated:
        return redirect('todo')
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        validate_user = authenticate(username=username, password=password)
        if validate_user is not None:
            login(request, validate_user)
            return redirect('about')
        else:
            messages.error(request, "invalid credentials")
            return redirect('login')
    return render(request, "login.html")


from django.contrib.auth.models import User
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib import messages
from django.contrib.auth import authenticate, login


def register(request):
    if request.user.is_authenticated:
        return redirect('todo')

    if request.method == "POST":
        username = request.POST.get("username")
        email = request.POST.get("email")
        password = request.POST.get("password")
        cpassword = request.POST.get("cpassword")

        # Password constraints validation
        from django.core.exceptions import ValidationError
        from django.contrib.auth.password_validation import validate_password
        try:
            validate_password(password)
        except ValidationError as e:
            messages.warning(request, e.messages[0])
            return redirect('register')

        if password != cpassword:
            messages.warning(request, "Passwords do not match.")
            return redirect('register')

        # Check if username or email already exists
        if User.objects.filter(username=username).exists():
            messages.warning(request, "Username already taken.")
            return redirect("register")

        if User.objects.filter(email=email).exists():
            messages.warning(request, "Email already exists.")
            return redirect("register")

        # Create user
        user = User.objects.create_user(username, email, password)
        user.save()

        # Optionally, log the user in
        user = authenticate(username=username, password=password)
        login(request, user)

        # Redirect to login page or some other page
        return redirect('login')

    return render(request, "register.html")


def aboutus(request):
    return render(request, "about.html")
