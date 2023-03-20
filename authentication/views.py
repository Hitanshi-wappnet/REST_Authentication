import random
from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from authentication.serializers import UserRegistrationSerializer
from rest_framework.authtoken.serializers import AuthTokenSerializer
from authentication.models import ForgetPassword
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
        # Validate user registration data with serializer
        serializer = UserRegistrationSerializer(data=request.data)
        if serializer.is_valid():
            # Create a new user with validated data
            serializer.save()

            # Return success response
            response = {
                "status": True,
                "message": "Registartion is Successfull!!"
            }
            return Response(data=response, status=status.HTTP_202_ACCEPTED)

        else:
            # Return error response with serializer errors
            response = {
                        "status": False,
                        "message": serializer.errors,
                        "data": None}
            return Response(data=response,
                            status=status.HTTP_400_BAD_REQUEST)


class UserLoginView(APIView):
    """
    API view for user login. User can be authenticated using email and password
    """

    def post(self, request):
        # validate serializer data
        email = request.data.get('email')
        password = request.data.get("password")
        if email is None or password is None:
            response = {
                        "status": False,
                        "message": "Provide email and password",
                        "data": None
                    }
            return Response(data=response,
                            status=status.HTTP_400_BAD_REQUEST)

        username = User.objects.get(email=email).username
        data = {
            "username": username,
            "password": password
        }
        serializer = AuthTokenSerializer(data=data)
        if serializer.is_valid():
            user = serializer.validated_data['user']
            # generate or get token for user
            token, _ = Token.objects.get_or_create(user=user)

            # check if user is active
            if not user.is_active:
                response = {
                    "status": False,
                    "message": "Activate user by admin",
                    "data": None
                }
                return Response(data=response,
                                status=status.HTTP_400_BAD_REQUEST)
            # Return success response
            response = {
                "status": True,
                "message": "Login is Successful!!",
                "token": token.key,
            }
            return Response(data=response, status=status.HTTP_202_ACCEPTED)
        else:
            response = {
                "status": False,
                "message": "Provide correct email and password",
                "data": None,
            }
            return Response(response, status=status.HTTP_400_BAD_REQUEST)


class UserChangePasswordView(APIView):

    """
    API View to change password if user is authenticated.
    """

    # Allow only authenticated users
    permission_classes = [IsAuthenticated]

    def post(self, request):
        username = request.data.get("username")
        old_password = request.data.get("password")
        new_password = request.data.get("newpassword")

        if username is None or old_password is None or new_password is None:
            response = {
                        "status": False,
                        "message": "Provide username,password and newpassword",
                        "data": None
                    }
            return Response(data=response,
                            status=status.HTTP_400_BAD_REQUEST)

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


class UserChangeProfileView(APIView):

    """
    API View to change user profile details if user is authenticated.
    """

    # Allow only authenticated users
    permission_classes = [IsAuthenticated]

    def post(self, request):
        username = request.data.get("username")
        firstname = request.data.get("firstname")

        if username is None or firstname is None:
            response = {
                        "status": False,
                        "message": "Provide username and firstname",
                        "data": None
                    }
            return Response(data=response,
                            status=status.HTTP_400_BAD_REQUEST)

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


class DeleteProfileView(APIView):

    """
    API View to delete user profile if user is authenticated.
    """

    # Allow only authenticated users
    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):
        username = request.data.get("username")

        if username is None:
            response = {
                "status": False,
                "message": "Provide username to delete profile",
                "data": None,
                }
            return Response(data=response, status=status.HTTP_400_BAD_REQUEST)
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


class UserForgetPasswordView(APIView):

    # This view handles sending a reset password email to a user
    def post(self, request):
        email = request.data.get('email')
        # Check if email was provided in the request
        if email is None:
            response = {
                    "status": False,
                    "message": "Provide email address!!",
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
                        "message": "Provide correct email id!!",
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
        new_otp = request.data.get('otp')
        if new_otp is None:
            response = {
                        "status": False,
                        "message": "Provide OTP!!",
                        "data": None
                    }
            return Response(data=response,
                            status=status.HTTP_400_BAD_REQUEST)

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


class UserResetPasswordView(APIView):

    # Allow only authenticated users
    permission_classes = [IsAuthenticated]

    def post(self, request, format=None):
        # Get username and new password from the request data
        username = request.data.get("username")
        new_password = request.data.get("newpassword")

        if username is None or new_password is None:
            response = {
                        "status": False,
                        "message": "Provide username and newpassword.",
                        "data": None,
                    }
            return Response(data=response,
                            status=status.HTTP_400_BAD_REQUEST)

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
