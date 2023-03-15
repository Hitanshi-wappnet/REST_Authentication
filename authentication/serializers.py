from rest_framework import serializers
from django.contrib.auth.models import User
from rest_framework.validators import UniqueValidator


# Register Serializer Class and defined Model and Fields
class UserRegistrationSerializer(serializers.ModelSerializer):
    # Checking uniqueness of email
    email = serializers.EmailField(
        validators=[UniqueValidator(queryset=User.objects.all())])
   
    # Password gets encrypted
    password = serializers.CharField(
        style={"input_type": "password", "write_only": True}
    )

    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        return user

    class Meta:
        model = User
        fields = ["first_name", "last_name", "email", "username", "password"]
        extra_kwarg = {"password": {"write_only": True}}


class UserLoginSeriaizers(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["email", "password"]
       

class UserProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ["first_name", "last_name", "email", "username"]


class UserChangePasswordSerializer(serializers.Serializer):
    class Meta:
        model = User
        fields = ["username", "password"]


class ChangeProfileSerializer(serializers.Serializer):
    class Meta:
        model = User
        fields = ["first_name", "last_name", "email", "username", "password"]


class DeleteProfileSerializer(serializers.Serializer):
    class Meta:
        model = User
        fields = ["username", "password"]