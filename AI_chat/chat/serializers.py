from rest_framework import serializers
from .models import User, Chat
from django.contrib.auth.hashers import make_password

class UserSerializer(serializers.ModelSerializer):
    class Meta:
        model = User
        fields = ['username', 'password']
        extra_kwargs = {
            'password': {'write_only': True}
        }

    def create(self, validated_data):
        user=User(
            username=validated_data['username'],
            password=make_password(validated_data['password']),
            tokens=4000
        )
        user.save()
        return user
    
    def validate_username(self, value):
        if User.objects.filter(username=value).exists():
            raise serializers.ValidationError("Username already exists!")
        return value

class ChatSerializer(serializers.ModelSerializer):
    class Meta:
        model = Chat
        fields = ['message']
