from django.utils.decorators import method_decorator
from drf_yasg import openapi
from drf_yasg.utils import swagger_auto_schema

from .serializers import UserSerializer
from rest_framework import generics, filters, pagination
from user.models import User
from rest_framework.response import Response
from rest_framework import status

"""
Using Generics View
"""


class UserListPagination(pagination.PageNumberPagination):
    page_size = 2


@method_decorator(
    name="get", decorator=swagger_auto_schema(operation_summary="Get all users")
)
class UserList(generics.ListAPIView):

    # is_active = True 인 entry 만 반환
    queryset = User.objects.filter(is_active=True).all()
    serializer_class = UserSerializer
    filter_backends = [filters.SearchFilter]
    search_fields = ["nickname", "email"]
    pagination_class = UserListPagination


@method_decorator(
    name="get",
    decorator=swagger_auto_schema(
        operation_summary="Get user by ID", responses={404: "Not found"}
    ),
)
@method_decorator(
    name="patch",
    decorator=swagger_auto_schema(
        operation_summary="Update user info",
        responses={400: "Invalid input", 401: "Authentication Failed"},
        # request_body=openapi.Schema(
        #     type=openapi.TYPE_OBJECT,
        #     properties={
        #         'nickname': openapi.Schema(type=openapi.TYPE_STRING, description="닉네임"),
        #         'profileMessage': openapi.Schema(type=openapi.TYPE_STRING, description="프로필 메시지"),
        #         'profileImage': openapi.Schema(type=openapi.TYPE_STRING, description="프로필 사진"),
        #     }
        # ),
    ),
)
class UserDetail(generics.RetrieveUpdateDestroyAPIView):

    queryset = User.objects.all()
    serializer_class = UserSerializer
    allowed_methods = ["get", "patch", "delete"]

    @swagger_auto_schema(
        operation_summary="Soft delete user",
        responses={
            200: openapi.Response("user", UserSerializer),
            400: "Invalid input",
            401: "Authentication Failed",
        },
    )
    def delete(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.is_active = False
        instance.save(update_fields=["is_active"])
        serializer = UserSerializer(instance)

        return Response(serializer.data, status=status.HTTP_200_OK)
