from django.db import IntegrityError
from rest_framework.authentication import TokenAuthentication
import random
from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from authentication.serializers import UserRegistrationSerializer
from authentication.serializers import UserLoginSeriaizers
from authentication.models import ForgetPassword
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from rest_framework.permissions import IsAuthenticated
from rest_framework.authtoken.models import Token
from django.core.mail import send_mail


# Create your views here.
class UserRegisterView(APIView):
    """
    API endpoint for creating a new user account using POST method.
    """
    def post(self, request):
        try:
            # Validate user registration data with serializer
            serializer = UserRegistrationSerializer(data=request.data)
            if serializer.is_valid(raise_exception=True):
                # Create a new user with validated data
                user = serializer.save()

                # Uncomment the following lines to deactivate new user's account
                # user.is_active = False
                # user.save()

                # Return success response
                response = {
                    "status": True,
                    "message": "Registartion is Successfull!!"
                }
                return Response(data=response, status=status.HTTP_202_ACCEPTED)
            else:
                # Return error response with serializer errors
                response = {"status": False,
                            "message": serializer.errors,
                            "data": None}
        except Exception:
            # Return error response for any exception raised
            response = {
                "status": False,
                "message": "Provide Credentials",
                "data": None,
            }
            return Response(data=response, status=status.HTTP_400_BAD_REQUEST)


class UserLoginView(APIView):
    """
    API view for user login. User can be authenticated using email and password
    """
    authentication_classes = [TokenAuthentication]

    def post(self, request):
        # validate serializer data
        serializer = UserLoginSeriaizers(data=request.data)
        try:
            if serializer.is_valid():
                email = request.data.get("email")
                password = request.data.get("password")
                # check if user with provided email exists
                if User.objects.filter(email=email).exists():
                    # get user using email and authenticate with provided password
                    username = User.objects.get(email=email).username
                    user = authenticate(username=username, password=password)

                    # generate or get token for user
                    token, _ = Token.objects.get_or_create(user=user)
                else:
                    response = {
                        "status": False,
                        "message": "Email dose not exist.",
                        "data": None,
                    }
                    return Response(data=response,
                                    status=status.HTTP_400_BAD_REQUEST)

                # check if provided password is correct
                if not user.check_password(password):
                    print("hello")
                    response = {
                            "status": False,
                            "message": "Provide correct Password",
                            "data": None
                        }
                    return Response(data=response,
                                    status=status.HTTP_400_BAD_REQUEST)

                # check if user is active
                if user is not None:
                    if user.is_active:
                        # Return success response
                        response = {
                            "status": True,
                            "message": "Login is Successful!!",
                            "token": token.key,
                        }
                        return Response(data=response,
                                        status=status.HTTP_202_ACCEPTED)
                    else:
                        response = {
                            "status": False,
                            "message": "Activate user by admin",
                            "data": None
                        }
                        return Response(data=response,
                                        status=status.HTTP_400_BAD_REQUEST)
            else:
                response = {
                    "status": False,
                    "message": "Please Provide correct Credentials of email and password",
                    "data": None,
                }
                return Response(data=response, 
                                status=status.HTTP_400_BAD_REQUEST)
        except IntegrityError:
            # Return error response for any Integrity exception raised
            response = {
                            "status": False,
                            "message": "Activate user by admin or provide correct password",
                            "data": None
                        }
            return Response(data=response,
                            status=status.HTTP_400_BAD_REQUEST)


class UserChangePasswordView(APIView):

    """
    API View to change password if user is authenticated.
    """

    # Use token authentication
    authentication_classes = [TokenAuthentication]
    # Allow only authenticated users
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            username = request.data.get("username")
            old_password = request.data.get("password")
            new_password = request.data.get("newpassword")
            # Retrieve the user from the database
            u = User.objects.get(username=username)

            # Check if the old password matches the user's password
            if u.check_password(old_password):
                # Set the user's new password
                u.set_password(new_password)

                # Save the user object with the new password
                u.save()

                # Return success response
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
        except Exception:
            # Return error response for any Integrity exception raised
            response = {
                    "status": False,
                    "message": "Provide Correct Credentials.",
                    "data": None,
                }
            return Response(data=response,
                            status=status.HTTP_400_BAD_REQUEST)


class UserChangeProfileView(APIView):

    """
    API View to change user profile details if user is authenticated.
    """
    # Use token authentication
    authentication_classes = [TokenAuthentication]

    # Allow only authenticated users
    permission_classes = [IsAuthenticated]

    def post(self, request):
        try:
            username = request.data.get("username")
            firstname = request.data.get("firstname")

            # Retrieving the user object using the username.
            u = User.objects.get(username=username)
            """
            If the username in the request matches the username of the
            retrieved user object, update the first name.
            """
            if u.username == username:
                u.first_name = firstname
                u.save()

                # Return a success response.
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
        except Exception:
            # Return error response for any exception raised
            response = {
                "status": False,
                "message": "Provide correct username and firstname to change",
                "data": None,
            }
            return Response(data=response, status=status.HTTP_400_BAD_REQUEST)


class DeleteProfileView(APIView):

    """
    API View to delete user profile if user is authenticated.
    """
    # Use token authentication
    authentication_classes = [TokenAuthentication]

    # Allow only authenticated users
    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):
        try:
            username = request.data.get("username")

            # Retrieving the user object using the username.
            u = User.objects.get(username=username)

            """
            If the username in the request matches the username of the
            retrieved user object,delete the user object.
            """
            if u.username == username:
                u.delete()
                # Return a success response.
                response = {
                    "status": True,
                    "message": "User Profile Deleted Successfully!!"
                }
                return Response(data=response, status=status.HTTP_200_OK)
            else:
                response = {
                    "status": False,
                    "message": "Provide Correct Credentials.",
                    "data": None
                }
                return Response(data=response,
                                status=status.HTTP_400_BAD_REQUEST)
        except Exception:
            # Return error response for any exception raised
            response = {
                "status": False,
                "message": "Provide correct username to delete profile",
                "data": None,
            }
            return Response(data=response, status=status.HTTP_400_BAD_REQUEST)


class UserForgetPasswordView(APIView):

    # This view handles sending a reset password email to a user
    def post(self, request):
        try:
            email = request.data.get('email')
            # Check if email was provided in the request
            if email is None:
                response = {
                        "status": False,
                        "message": "Please provide correct email name!!",
                        "data": None
                    }
                return Response(data=response,
                                status=status.HTTP_200_OK)

            # Check if a user with that email exists
            if User.objects.filter(email=email).exists():
                user = User.objects.get(email=email)

                # Generate a random 4-digit OTP and save it in the database
                otp = random.randint(1000, 9999)
                generated_otp = otp

                # Save the OTP to the database
                Forget_password = ForgetPassword(user=user, otp=generated_otp)
                Forget_password.save()

                # Send an email to the user containing the OTP
                subject = "Forget password"
                message = "Here is the otp to Reset your password." + str(otp)
                send_mail(
                    subject,
                    message,
                    settings.EMAIL_HOST_USER,
                    [user.email],
                    fail_silently=False
                )

                # Return a success response.
                response = {
                        "status": True,
                        "message": "Email sent!!",
                        "data": None
                    }
                return Response(data=response,
                                status=status.HTTP_200_OK)
            else:
                # If no user with that email exists, return an error message
                response = {
                            "status": False,
                            "message": "Email does ot exist!!",
                            "data": None
                        }
                return Response(data=response,
                                status=status.HTTP_400_BAD_REQUEST)
        except Exception:
            # If an error occurs, return an error message
            response = {
                            "status": False,
                            "message": "Provide correct Email id!!",
                            "data": None
                        }
            return Response(data=response,
                            status=status.HTTP_400_BAD_REQUEST)


class UserVerifyOtpView(APIView):
    """
    This view handles verifying an OTP and generating
    a new auth token for the user
    """
    def post(self, request):
        try:
            new_otp = request.data.get('otp')

            # Get the ForgetPassword object with the given OTP
            forget_password = ForgetPassword.objects.get(otp=new_otp)

            user = forget_password.user
            if user:
                # Delete the user's old auth token and generate a new one
                token = Token.objects.get(user=forget_password.user)
                token.delete()
                forget_password.delete()
                token = Token.objects.create(user=user)
                # Return a success response.
                response = {
                            "status": True,
                            "message": "OTP Verified SuccessFully!!",
                            "Token": token.key
                        }
                return Response(data=response,
                                status=status.HTTP_200_OK)
            else:
                # If the OTP is incorrect, return an error message
                response = {
                            "status": False,
                            "message": "OTP is incorrect!!",
                            "data": None
                        }
                return Response(data=response,
                                status=status.HTTP_400_BAD_REQUEST)
        except Exception:
            # If an error occurs, return an error message
            response = {
                            "status": False,
                            "message": "Please provide correct otp!!",
                            "data": None
                        }
            return Response(data=response,
                            status=status.HTTP_400_BAD_REQUEST)


class UserResetPasswordView(APIView):

    # This view handles Resetting User's password

    # Use token authentication
    authentication_classes = [TokenAuthentication]

    # Allow only authenticated users
    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):
        try:
            # Get username and new password from the request data
            username = request.data.get("username")
            new_password = request.data.get("newpassword")

            # Get the user object based on the username
            u = User.objects.get(username=username)

            # Check if the user object matches the provided username
            if str(u) == username:
                # Set the user's password to the new password and save
                u.set_password(new_password)
                u.save()

                # Return a success response.
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
        except Exception:
            # If an error occurs, return an error message
            response = {
                            "status": False,
                            "message": "Provide Correct username and newpassword.",
                            "data": None,
                        }
            return Response(data=response,
                            status=status.HTTP_400_BAD_REQUEST)
