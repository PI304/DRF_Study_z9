import string
import random
from rest_framework_simplejwt.tokens import RefreshToken


class UserServices:
    @staticmethod
    def deactivate_user(user):
        user.is_active = False
        user.save(update_fields=["is_active"])
        return user

    @staticmethod
    def generate_random_code(number_of_strings, length_of_string):
        for x in range(number_of_strings):
            return "".join(
                random.choice(string.ascii_letters + string.digits)
                for _ in range(length_of_string)
            )

    @staticmethod
    def get_tokens_for_user(user):
        refresh = RefreshToken.for_user(user)

        return {
            "refresh": str(refresh),
            "access": str(refresh.access_token),
        }
