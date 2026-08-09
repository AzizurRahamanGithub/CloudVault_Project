from django.shortcuts import render

from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from django.contrib.auth import authenticate
from rest_framework_simplejwt.tokens import RefreshToken
from rest_framework.permissions import AllowAny
from .serializers import UserLoginSerializer

# Create your views here.


class BaseAPIView(APIView):
    
    def success_response(self, message="Thank you for your request", data=None, status_code= status.HTTP_200_OK):
        return Response(
            {
            "success": True,
            "message": message,
            "status_code": status_code,
            "data": data or {}
            }, 
            status=status_code )
        
    def error_response(self, message="I am sorry for your request", data=None, status_code= status.HTTP_400_BAD_REQUEST):
        return Response(
            {
            "success": False,
            "message": message,
            "status_code": status_code,
            "data": data or {}
            }, 
            status=status_code )    
        





class UserLoginView(BaseAPIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = UserLoginSerializer(data=request.data)

        try:
            serializer.is_valid(raise_exception=True)
            username = serializer.validated_data['username']
            password = serializer.validated_data['password']

            user = authenticate(username=username, password=password)

            if user is None:
                return self.error_response(
                    message="Invalid username or password",
                    status_code=status.HTTP_401_UNAUTHORIZED,
                    data= serializer.data
                )

            if not user.is_active:
                return self.error_response(
                    message="User account is disabled",
                    status_code=status.HTTP_403_FORBIDDEN,
                    data= serializer.data
                )

            refresh = RefreshToken.for_user(user)
            access_token = str(refresh.access_token)

            return self.success_response(
                message="Login successful",
                status_code=status.HTTP_200_OK,
                data={
                    "refresh_token": str(refresh),
                    "access_token": access_token,
                    "user": {
                        "id": user.id,
                        "username": user.username,
                    }
                }
            )

        except Exception as e:
            return self.error_response(
                message=f"An unexpected error occurred: {str(e)}",
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    data= serializer.data
            )