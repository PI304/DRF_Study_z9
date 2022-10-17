from django.db import models
from django.contrib.auth.models import PermissionsMixin
from django.contrib.auth.base_user import AbstractBaseUser, BaseUserManager


class UserManager(BaseUserManager):
    """
    Custom user model manager where email is the unique identifiers
    for authentication instead of usernames.
    """

    use_in_migrations = True

    def create_user(
        self,
        email=None,
        password=None,
        **extra_fields,
    ):
        """
        Create and save a User with the given email and password.
        """
        extra_fields.setdefault("is_superuser", False)

        if not email:
            raise ValueError("Email field must be set")
        email = self.normalize_email(email)
        user = self.model(email=email, **extra_fields)
        user.set_password(password)

        user.save(using=self._db)
        return user

    def create_superuser(self, email, password, **extra_fields):
        """
        Create and save a SuperUser with the given email and password.
        """
        extra_fields.setdefault("is_superuser", True)
        extra_fields.setdefault("nickname", "admin")

        if extra_fields.get("is_superuser") is not True:
            raise ValueError("Superuser must have is_superuser=True.")

        return self.create_user(email=email, password=password, **extra_fields)


class TimeStampMixin(models.Model):
    """
    abstract timestamp mixin base model for created_at, updated_at field
    """

    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        abstract = True


class User(AbstractBaseUser, PermissionsMixin, TimeStampMixin):
    id = models.BigAutoField(primary_key=True)
    email = models.EmailField(max_length=64, unique=True, null=False)
    nickname = models.CharField(
        max_length=20, null=False, blank=False, help_text="서비스 상에서 사용되는 이름"
    )
    profile_image_url = models.URLField(
        max_length=256, blank=True, default="", null=True
    )  # TODO: default profile image
    profile_message = models.CharField(max_length=200, blank=True, null=True)
    is_active = models.BooleanField(default=True, null=False)

    # 헬퍼 클래스 지정
    objects = UserManager()

    EMAIL_FIELD = "email"

    # 유저 모델의 unique identifier, unique = True 인 필드 값으로 설정함
    USERNAME_FIELD = "email"

    # 필수로 받고 싶은 필드 값, USERNAME_FIELD 와 password 는 항상 기본적으로 요구하기 때문에 따로 명시 X
    REQUIRED_FIELDS = ["nickname"]

    class Meta:
        db_table = "user"
        unique_together = ["email"]

    def __str__(self):
        return f"[{self.id}] {self.get_username()}"

    def __repr__(self):
        return f"User({self.id}, {self.get_username()})"
