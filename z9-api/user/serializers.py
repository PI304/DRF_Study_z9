from django.contrib.auth import get_user_model
from rest_framework import serializers

User = get_user_model()


class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = [
            "id",
            "email",
            "nickname",
            "profile_image_url",
            "profile_message",
            "last_login",
            "is_active",
            "created_at",
            "updated_at",
        ]
        # api 로 get 만 할 필드
        read_only_fields = [
            "id",
            "last_login",
            "is_active",
            "created_at",
            "updated_at",
        ]
