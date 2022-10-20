from .serializers import UserSerializer
from rest_framework import generics
from user.models import User
from rest_framework.response import Response
from rest_framework import status
from datetime import datetime

"""
Using Generics View
"""


class UserList(generics.ListCreateAPIView):

    # is_active = True 인 entry 만 반환
    queryset = User.objects.filter(is_active=True).all()
    serializer_class = UserSerializer


class UserDetail(generics.RetrieveUpdateDestroyAPIView):

    queryset = User.objects.all()
    serializer_class = UserSerializer

    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        user = self.get_object()
        serializer = self.get_serializer(user, data=request.data, partial=partial)

        serializer.is_valid(raise_exception=True)

        serializer.save(
            updated_at=datetime.now()
        )
        return Response(serializer.data, status=status.HTTP_200_OK)

    def delete(self, request, *args, **kwargs):
        instance = self.get_object()
        instance.is_active = False
        instance.save(update_fields=["is_active"])
        serializer = UserSerializer(instance)

        return Response(serializer.data, status=status.HTTP_200_OK)



