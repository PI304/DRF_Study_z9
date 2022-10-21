from rest_framework import viewsets
from user.models import User
from user.serializers import UserSerializer

"""
Using Viewsets
"""

class UserViewSet(viewsets.ModelViewSet):
    """
        This viewset automatically provides `list`, `create`, `retrieve`,
        `update` and `destroy` actions.

        Can additionally provide extra actions with @action annotation.
    """
    queryset = User.objects.all()
    serializer_class = UserSerializer
