from rest_framework import serializers
from django.contrib.auth.models import User
from rest_framework.validators import UniqueValidator


# Serializer for user registration
class UserRegistrationSerializer(serializers.ModelSerializer):

    # Use a validator to ensure email is unique
    email = serializers.EmailField(
        validators=[UniqueValidator(queryset=User.objects.all())])

    # Use a password field to ensure password is write_only and encrypted
    password = serializers.CharField(
        style={"input_type": "password", "write_only": True}
    )

    # Create a new user with the validated data
    def create(self, validated_data):
        user = User.objects.create_user(**validated_data)
        return user

    # Define the model and fields for the serializer
    class Meta:
        model = User
        fields = ["first_name", "last_name", "email", "username", "password"]
        extra_kwarg = {"password": {"write_only": True}}


# Serializer for user login
class UserLoginSeriaizers(serializers.ModelSerializer):

    # Define the model and fields for the serializer
    class Meta:
        model = User
        fields = ["email", "password"]
