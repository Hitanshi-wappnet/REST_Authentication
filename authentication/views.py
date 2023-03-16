from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from authentication.serializers import UserRegistrationSerializer
from authentication.serializers import UserLoginSeriaizers
from authentication.serializers import UserChangePasswordSerializer
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from rest_framework.permissions import IsAuthenticated
from django.contrib.auth.hashers import make_password


# Create your views here.
class UserRegisterView(APIView):
    """
    created a new User using POST Method.
    """

    def post(self, request):
        try:
            serializer = UserRegistrationSerializer(data=request.data)
            if serializer.is_valid(raise_exception=True):
                serializer.save()
                response = {
                    "status": True,
                    "message": "Registartion is Successfull!!",
                }
                return Response(data=response, status=status.HTTP_202_ACCEPTED)
            else:
                response = {"status": False,
                            "message": serializer.errors,
                            "data": None}
        except:
            response = {
                "status": False,
                "message": "Provide Credentials",
                "data": None,
            }
            return Response(data=response, status=status.HTTP_400_BAD_REQUEST)


class UserLoginView(APIView):
    """
    If User is authenticated with email and password then only
    authentication process is done.
    """

    def post(self, request):
        serializer = UserLoginSeriaizers(data=request.data)
        if serializer.is_valid():
            email = request.data.get("email")
            password = request.data.get("password")
            if User.objects.filter(email=email).exists():
                username = User.objects.get(email=email).username
                user = authenticate(username=username, password=password)
            else:
                response = {
                    "status": False,
                    "message": "Email dose not exist.",
                    "data": None,
                }
                return Response(data=response,
                                status=status.HTTP_400_BAD_REQUEST)

            if user is not None:
                if user.is_active:
                    response = {
                        "status": True,
                        "message": "Login is Successful!!",
                    }
                    return Response(data=response,
                                    status=status.HTTP_202_ACCEPTED)

            if user is not None and not user.is_active:
                response = {
                    "status": False,
                    "message": "Activate user by admin",
                    "data": None,
                }
                return Response(data=response,
                                status=status.HTTP_400_BAD_REQUEST)
            else:
                response = {
                    "status": False,
                    "message": "Please Provide correct Credentials",
                    "data": None,
                }
            return Response(data=response, status=status.HTTP_400_BAD_REQUEST)
        else:
            response = {
                "status": False,
                "message": "Please Provide Credentials",
                "data": None,
            }
            return Response(data=response, status=status.HTTP_400_BAD_REQUEST)


class UserChangePasswordView(APIView):

    """
    If User is Authenticated then only
    User can change password by providing correct username,
    oldpassword and newpassword.
    """

    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):
        try:
            username = request.data.get("username")
            old_password = request.data.get("password")
            new_password = request.data.get("newpassword")
            serializer = UserChangePasswordSerializer(data=request.data)
            if serializer.is_valid():
                u = User.objects.get(username=username)
                if u.check_password(old_password):
                    u.set_password(new_password)
                    u.save()
                    response = {
                        "status": True,
                        "message": "Password Changed Successfully.",
                    }
                    return Response(data=response, status=status.HTTP_200_OK)
                else:
                    response = {
                        "status": False,
                        "message": "Provide Correct Credentials.",
                        "data": None,
                    }
                    return Response(data=response,
                                    status=status.HTTP_400_BAD_REQUEST)
        except:
            response = {
                "status": False,
                "message": "Provide username, Oldpassword and newpassword",
                "data": None,
            }
            return Response(data=response, status=status.HTTP_400_BAD_REQUEST)


class UserChangeProfileView(APIView):

    """
    If User is Authenticated then only
    User can update profile by providing correct username
    and changed first name.
    """

    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            serializer = UserChangePasswordSerializer(data=request.data)
            if serializer.is_valid():
                username = request.data.get("username")
                firstname = request.data.get("firstname")
                u = User.objects.get(username=username)
                if u.username == username:
                    u.first_name = firstname
                    u.save()
                    response = {
                        "status": True,
                        "message": "First name Changed Successfully.",
                    }
                    return Response(data=response, status=status.HTTP_200_OK)
                else:
                    response = {
                        "status": False,
                        "message": "Provide Correct Credentials.",
                        "data": None,
                    }
                    return Response(data=response,
                                    status=status.HTTP_400_BAD_REQUEST)
        except:
            response = {
                "status": False,
                "message": "Provide username and firstname to change",
                "data": None,
            }
            return Response(data=response, status=status.HTTP_400_BAD_REQUEST)


class DeleteProfileView(APIView):

    """
    If User is Authenticated then only
    User can delte profile by giving correct username.
    """

    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):
        try:
            serializer = UserChangePasswordSerializer(data=request.data)
            username = request.data.get("username")
            if serializer.is_valid():
                u = User.objects.get(username=username)
                if u.username == username:
                    u.delete()
                    response = {
                        "status": True,
                        "message": "User Profile Deleted Successfully!!",
                    }
                    return Response(data=response, status=status.HTTP_200_OK)
                else:
                    response = {
                        "status": False,
                        "message": "Provide Correct Credentials.",
                    }
                    return Response(data=response,
                                    status=status.HTTP_400_BAD_REQUEST)
        except:
            response = {
                "status": False,
                "message": "Provide username to delete profile",
                "data": None,
            }
            return Response(data=response, status=status.HTTP_400_BAD_REQUEST)
