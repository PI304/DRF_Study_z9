from django.contrib.auth.models import update_last_login
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from rest_framework.permissions import AllowAny
from rest_framework.views import APIView
from rest_framework.exceptions import AuthenticationFailed

from config.exceptions import PasswordNotMatch
from config.renderer import CustomRenderer
from user.models import User
from rest_framework.response import Response
from rest_framework import status, generics, permissions
from django.contrib.auth.hashers import check_password
from django.core.mail import EmailMessage
from config.settings import EMAIL_HOST_USER

from user.serializers import UserSerializer
from user.services import UserServices


class BasicSignUpView(APIView):
    serializer_class = UserSerializer
    renderer_classes = [CustomRenderer]
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):

        password = request.data.get("password")
        confirm_password = request.data.get("confirm_password")

        if password != confirm_password:
            raise PasswordNotMatch

        email = request.data.get("email")
        nickname = request.data.get("nickname")

        user = User.objects.create_user(email=email, password=password, nickname=nickname)

        serializer = UserSerializer(user)

        return Response(serializer.data, status=status.HTTP_201_CREATED)


class BasicSignInView(APIView):
    serializer = UserSerializer
    renderer_classes = [CustomRenderer]
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        email = request.data.get("email")
        password = request.data.get("password")

        user = get_object_or_404(User, email=email)
        if not check_password(password, user.password):
            raise AuthenticationFailed

        update_last_login(None, user)
        serializer = UserSerializer(user)

        return Response(serializer.data, status=status.HTTP_200_OK)


class SecessionView(APIView):
    renderer_classes = [CustomRenderer]
    serializer = UserSerializer

    def update(self, request, *args, **kwargs):
        user = UserServices.deactivate_user(request.user)
        serializer = UserSerializer(user)

        return Response(serializer.data, status=status.HTTP_200_OK)


class CheckDuplicateUsernameView(APIView):
    renderer_classes = [CustomRenderer]
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        email = request.data.get("email")

        existing_email = User.objects.filter(email=email).first()
        if existing_email:
            return Response({"details": "Provided email already exists."}, status=status.HTTP_409_CONFLICT)

        return Response({"email": email}, status=status.HTTP_200_OK)


class PasswordChangeView(APIView):
    serializer = UserSerializer
    renderer_classes = [CustomRenderer]

    def post(self, request, *args, **kwargs):
        user = request.user
        current_password = request.data.get("current_password")
        new_password = request.data.get("new_password")

        if not check_password(current_password, user.password):
            raise AuthenticationFailed

        user.set_password(new_password)
        user.save(update_fields=["password"])

        serializer = UserSerializer(user)
        return Response(serializer.data, status=status.HTTP_200_OK)


class PasswordResetView(APIView):
    renderer_classes = [CustomRenderer]

    def post(self, request, *args, **kwargs):
        # jwt 구현 시 완성할 예정
        pass


class EmailVerification(APIView):
    renderer_classes = [CustomRenderer]
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        email = request.data.get("email")
        generated_code = UserServices.generate_random_code()

        # set code in cookie
        res = JsonResponse({'success': True})
        res.set_cookie('email_verification_code', generated_code, max_age=300)

        # send email
        email = EmailMessage(
            "[ChatMate] 이메일 인증 코드입니다.",
            generated_code,
            to=[email],  # 받는 이메일
        )
        success = email.send()

        if success > 0:
            return Response(status=status.HTTP_200_OK)
        elif success == 0:
            return Response({"details": "Failed to send email"},status=status.HTTP_400_BAD_REQUEST)


class EmailConfirmation(APIView):
    permission_classes = [AllowAny]

    def post(self, request, *args, **kwargs):
        if 'email_verification_code' in request.COOKIES:
            code_cookie = request.COOKIES['email_verification_code']
        else:
            return Response({"details": "No cookies attached"}, status=status.HTTP_400_BAD_REQUEST)

        code_input = request.data.get("verification_code")
        if code_cookie == code_input:
            return Response(status=status.HTTP_200_OK)
        else:
            return Response({"details": "Verification code does not match."}, status=status.HTTP_400_BAD_REQUEST)