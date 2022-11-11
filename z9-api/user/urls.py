from django.urls import path
from user import generics_views

urlpatterns = [
    path("", generics_views.UserList.as_view(), name="user_list"),
    path("<int:pk>/", generics_views.UserDetail.as_view(), name="user_detail"),
]
