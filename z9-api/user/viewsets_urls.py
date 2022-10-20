from django.urls import path
from rest_framework.urlpatterns import format_suffix_patterns
from .viewsets_views import UserViewSet


user_list = UserViewSet.as_view({
    'get': 'list',
    'post': 'create'
})

user_detail = UserViewSet.as_view({
    'get': 'retrieve',
    'patch': 'partial_update',
})

urlpatterns = format_suffix_patterns([
    path("", user_list, name="user_list"),
    path("<int:pk>/", user_detail, name="user_detail")
])