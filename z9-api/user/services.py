import string
import random

class UserServices:
    @staticmethod
    def deactivate_user(user):
        user.is_active = False
        user.save(update_fields=["is_active"])
        return user

    @staticmethod
    def generate_random_code():
        number_of_strings = 5
        length_of_string = 8
        for x in range(number_of_strings):
            return ''.join(random.choice(string.ascii_letters + string.digits) for _ in range(length_of_string))
