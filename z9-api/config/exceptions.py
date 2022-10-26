from rest_framework.views import exception_handler
from rest_framework import exceptions
from django.http import Http404


def custom_exception_handler(exc, context):
    # Call REST framework's default exception handler first,
    # to get the standard error response.
    response = exception_handler(exc, context)

    # Update the structure of the response data.
    if response is not None:
        if isinstance(exc, Http404):
            customized_response = {"code": response.status_code, "details": "Not Found"}
        elif isinstance(exc, exceptions.NotFound):
            customized_response = {"code": response.status_code, "details": exc.detail}
        elif isinstance(exc, exceptions.MethodNotAllowed):
            customized_response = {"code": response.status_code, "details": exc.detail}
        elif isinstance(exc, exceptions.NotAcceptable):
            customized_response = {"code": response.status_code, "details": exc.detail}
        elif isinstance(exc, exceptions.UnsupportedMediaType):
            customized_response = {"code": response.status_code, "details": exc.detail}
        elif isinstance(exc, exceptions.AuthenticationFailed):
            customized_response = {"code": response.status_code, "details": exc.detail}
        elif isinstance(exc, exceptions.PermissionDenied):
            customized_response = {"code": response.status_code, "details": exc.detail}
        elif isinstance(exc, exceptions.NotAuthenticated):
            customized_response = {"code": response.status_code, "details": exc.detail}
        else:
            customized_response = {
                "code": response.status_code,
                "details": response.data,
            }

        response.data = customized_response

    return response
