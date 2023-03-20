# REST_Authentication
authentication using REST API.

## Requirements

To run this files makes sure Python,Python-Django,django REST Framework and environ installed first. To install them use following command.

``pip install -r requirements.txt``

## Quick Start

1. Run ``python manage.py migrate`` to migrate tables.

2. Run this files using ``python manage.py runserver`` command.

3. Make admin using ``python manage.py createsuperuser`` command and provide username, 
   email and password.

4. Test the Register API using http://127.0.0.1:8000/api/register/ and provide first_name, last_name,
   email, username and password.

5. Test the Login API using http://127.0.0.1:8000/api/login/ and provide email and password.

6. Test the changepassword API using http://127.0.0.1:8000/api/changepassword/ and provide username,
   password and newpassword.

7. Test the changeprofile API using http://127.0.0.1:8000/api/changeprofile/ and provide username,
   firstname.This is only applied to firstname but in the same way you can update all fields.

8. Test the deleteprofile API using http://127.0.0.1:8000/api/deleteprofile/ and provide username
   to delete profile.

9. Make sure to perform changepassword, changeprofile and deleteprofile Token authentication is required.

10. Test the Forget Password API by providing registered email id and then you received otp on
   this email id.

11. Test the Verify otp API by providing correct otp.

12. Test the Reset Paasword API using resetting password for correct email id.