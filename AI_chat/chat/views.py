from django.shortcuts import render
from rest_framework import status, permissions
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.exceptions import AuthenticationFailed, PermissionDenied
from .serializers import UserSerializer, ChatSerializer
from .models import User, Chat
import datetime, jwt
from django.contrib.auth.hashers import check_password
from django.conf import settings

def home(request):
    return render(request, 'chat/base.html')

class RegisterView(APIView):
    permission_classes = [permissions.AllowAny]
    def post(self, request):
        serializer = UserSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        serializer.save()
        return Response(serializer.data)
    
class LoginView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')

        if not username or not password:
            return Response({"error": "Email and password are required!"}, status=status.HTTP_400_BAD_REQUEST)
        
        user = User.objects.filter(username=username).first()
        if user is None:
            raise AuthenticationFailed("User not found!")
        
        if not check_password(password, user.password):
            raise AuthenticationFailed("Incorrect password!")
        
        
        payload = {
            'id': user.id,
            'exp': datetime.datetime.utcnow() + datetime.timedelta(minutes=60),
            'iat': datetime.datetime.utcnow()
        }

        token = jwt.encode(payload, settings.SECRET_KEY, algorithm='HS256')

        response = Response()
        response.set_cookie(key='jwt', value=token, httponly=True)
        response.data = {
            "user": user.username,
            "tokens": user.tokens,
            "token": token
        }

        return response

class LogoutView(APIView):
    permission_classes = [permissions.AllowAny]
    def post(self, request):
        response = Response()
        response.delete_cookie('jwt')
        response.data = {
            'message': 'Logout Done'
        }
        return response

class TokenBalanceView(APIView):
    permission_classes = [permissions.AllowAny]
    def get(self, request):
        token = request.COOKIES.get('jwt')

        if not token:
            raise AuthenticationFailed('Unauthenticated!, Login please', code=status.HTTP_401_UNAUTHORIZED)
        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed('Unauthenticated!')
        except jwt.InvalidTokenError:
            raise AuthenticationFailed('Invalid token!')

        user = User.objects.filter(id=payload['id']).first() # first() just to be safe (id is unique attribute)
        serializer = UserSerializer(user)
        if not user:
            raise AuthenticationFailed('User not found!')

        return Response(
            {
                'username': user.username,
                'tokens': user.tokens
            }
        )
        
class ChatView(APIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        token = request.COOKIES.get('jwt')
        if not token:
            raise AuthenticationFailed("Authentication token is required!")

        try:
            payload = jwt.decode(token, settings.SECRET_KEY, algorithms=['HS256'])
            user = User.objects.get(id=payload['id'])
        except jwt.ExpiredSignatureError:
            raise AuthenticationFailed("Authentication token has expired!")
        except jwt.InvalidTokenError:
            raise AuthenticationFailed("Invalid authentication token!")
        
        if user.tokens < 100:
            raise PermissionDenied("Insufficient tokens to ask a question!")
        
        message = request.data.get('message')
        if not message:
            return Response({'error': "Message is required!"})
        
        user.tokens -= 100
        user.save()

        response = "This is a dummy AI response."

        chat = Chat.objects.create(user=user, message=message, response=response)
        
        return Response(
            {
                'message': chat.message,
                'response': chat.response,
                'timestamp': chat.timestamp,
                'remaining_tokens': user.tokens
            }, status=status.HTTP_200_OK
        )



