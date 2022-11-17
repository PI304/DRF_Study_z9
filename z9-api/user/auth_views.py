from django.contrib.auth.models import update_last_login
from django.http import JsonResponse, Http404
from django.shortcuts import get_object_or_404
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema
from rest_framework.permissions import AllowAny
from rest_framework.views import APIView
from rest_framework.exceptions import AuthenticationFailed, NotFound
from rest_framework_simplejwt.authentication import JWTAuthentication
from rest_framework_simplejwt.exceptions import InvalidToken
from rest_framework_simplejwt.serializers import TokenRefreshSerializer

from config.authentication import RefreshTokenAuthentication
from config.exceptions import PasswordNotMatch
from config.renderer import CustomRenderer
from user.models import User
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth.hashers import check_password
from django.core.mail import EmailMessage
from config import settings

from user.serializers import UserSerializer
from user.services import UserServices


class BasicSignUpView(APIView):
    serializer_class = UserSerializer
    renderer_classes = [CustomRenderer]
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_summary="Sign up",
        responses={
            201: openapi.Response("user", UserSerializer),
            400: "Passwords doesn't match"
        },
    )
    def post(self, request, *args, **kwargs):

        password = request.data.get("password")
        confirm_password = request.data.get("confirm_password")

        if password != confirm_password:
            raise PasswordNotMatch

        email = request.data.get("email")
        nickname = request.data.get("nickname")

        user = User.objects.create_user(
            email=email, password=password, nickname=nickname
        )

        serializer = UserSerializer(user)

        return Response(serializer.data, status=status.HTTP_201_CREATED)


class BasicSignInView(APIView):
    serializer = UserSerializer
    renderer_classes = [CustomRenderer]
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_summary="Sign In",
        responses={
            201: openapi.Response("user", UserSerializer),
            401: "Incorrect password",
            404: "User not found"
        },
    )
    def post(self, request, *args, **kwargs):
        email = request.data.get("email")
        password = request.data.get("password")

        try:
            user = get_object_or_404(User, email=email)
        except Http404:
            raise NotFound("User does not exist")

        if not check_password(password, user.password):
            raise AuthenticationFailed("Incorrect password")

        update_last_login(None, user)
        serializer = UserSerializer(user)

        token = UserServices.get_tokens_for_user(user)

        res = Response(
            data=dict(user=serializer.data, access_token=token["access"]),
            status=status.HTTP_200_OK,
        )
        res.set_cookie(
            settings.SIMPLE_JWT["AUTH_COOKIE"],
            token["refresh"],
            max_age=60 * 60 * 24 * 14,
        )  # 2 weeks

        return res


class SecessionView(APIView):
    renderer_classes = [CustomRenderer]
    serializer = UserSerializer

    @swagger_auto_schema(
        operation_summary="Leave",
        responses={
            200: openapi.Response("user", UserSerializer)
        },
    )
    def update(self, request, *args, **kwargs):
        user = UserServices.deactivate_user(request.user)
        serializer = UserSerializer(user)

        return Response(serializer.data, status=status.HTTP_200_OK)


class CheckDuplicateUsernameView(APIView):
    renderer_classes = [CustomRenderer]
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_summary="Check if there's duplicate email (username)",
        responses={
            200: openapi.Response(
                description="No duplicates",
                schema=openapi.Schema(
                    type=openapi.TYPE_OBJECT,
                    properties={
                        "email": openapi.Schema(type=openapi.TYPE_STRING, description="email"),
                    }
                )
            ), 409: "Provided email already exists."}
        )
    def post(self, request, *args, **kwargs):
        email = request.data.get("email")

        existing_email = User.objects.filter(email=email).first()
        if existing_email:
            return Response(
                {"details": "Provided email already exists."},
                status=status.HTTP_409_CONFLICT,
            )

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
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_summary="Reset password to random string sent to user email",
        responses={
            404: "User with the provided email does not exist",
            500: "Failed to send email. Try again later."
        }
    )
    def post(self, request, *args, **kwargs):
        email = request.data.get("email")

        try:
            user = get_object_or_404(User, email=email)
        except Http404:
            raise NotFound("User with the provided email does not exist")

        new_password = UserServices.generate_random_code(3, 8)
        user.set_password(new_password)
        user.save(update_fields=["password"])

        email = EmailMessage(
            "[ChatMate] 비밀번호가 초기화 되었습니다.",
            f"비밀번호가 아래의 임시 비밀번호로 변경되었습니다. 아래 비밀번호로 다시 로그인하신 뒤 꼭 비밀번호를 변경해주세요.\n임시 비밀번호: {new_password}",
            to=[email],  # 받는 이메일
        )
        success = email.send()

        if success > 0:
            return Response(status=status.HTTP_200_OK)
        elif success == 0:
            return Response(
                {"details": "Failed to send email. Try again later."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class EmailVerification(APIView):
    renderer_classes = [CustomRenderer]
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_summary="Verify code sent to user email when signing up",
        responses={
            500: "Failed to send email. Try again later or try with a valid email."
        }
    )
    def post(self, request, *args, **kwargs):
        email = request.data.get("email")
        generated_code = UserServices.generate_random_code(5, 8)

        # set code in cookie
        res = JsonResponse({"success": True})
        res.set_cookie("email_verification_code", generated_code, max_age=300)

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
            return Response(
                {"details": "Failed to send email. Try again later or try with a valid email."},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class EmailConfirmation(APIView):
    permission_classes = [AllowAny]

    @swagger_auto_schema(
        operation_summary="Confirm code sent to email for signing up",
        responses={
            400: "No cookies attached",
            409: "Verification code does not match",
        }
    )
    def post(self, request, *args, **kwargs):
        if "email_verification_code" in request.COOKIES:
            code_cookie = request.COOKIES.get("email_verification_code")
        else:
            return Response(
                {"details": "No cookies attached"}, status=status.HTTP_400_BAD_REQUEST
            )

        code_input = request.data.get("verification_code")
        if code_cookie == code_input:
            return Response(status=status.HTTP_200_OK)
        else:
            return Response(
                {"details": "Verification code does not match"},
                status=status.HTTP_409_CONFLICT,
            )


class TokenRefreshView(APIView):
    """
    Refresh tokens and returns a new pair.
    """

    authentication_classes = [RefreshTokenAuthentication]
    permission_classes = [AllowAny]
    renderer_classes = [CustomRenderer]

    @swagger_auto_schema(
        operation_summary="Refresh token",
        responses={
            201: openapi.Response("Pair of new tokens", TokenRefreshSerializer),
            401: "Authentication Failed",
        },
    )
    def post(self, request, *args, **kwargs):

        refresh_token = request.COOKIES.get(settings.SIMPLE_JWT["AUTH_COOKIE"]) or None
        access_token = request.META.get("HTTP_AUTHORIZATION") or None

        # authenticate() verifies and decode the token
        # if token is invalid, it raises an exception and returns 401
        refresh_token_authenticator = RefreshTokenAuthentication()
        access_token_authenticator = JWTAuthentication()

        try:
            access_token_validation = access_token_authenticator.authenticate(request)
            return Response(
                "Access token not expired", status=status.HTTP_204_NO_CONTENT
            )
        except InvalidToken:
            # access_token is invalid
            try:
                user, validated_token = refresh_token_authenticator.authenticate(
                    request
                )
                new_tokens = UserServices.get_tokens_for_user(user)
                res = Response(new_tokens, status=status.HTTP_201_CREATED)
                res.set_cookie(
                    settings.SIMPLE_JWT["AUTH_COOKIE"],
                    new_tokens["refresh"],
                    max_age=60 * 60 * 24 * 14,
                )  # 2 weeks
                return res

            except InvalidToken:
                raise AuthenticationFailed("Both tokens are invalid. Login again.", 401)
