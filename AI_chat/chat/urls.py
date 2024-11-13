from django.urls import path, include
from .views import home, RegisterView, LoginView, ChatView, TokenBalanceView, LogoutView
urlpatterns = [
    path('', home, name='home'),
    path('register/', RegisterView.as_view(), name='register'),
    path('login/', LoginView.as_view(), name='login'),
    path('logout/', LogoutView.as_view(), name='logout'),
    path('chat/', ChatView.as_view(), name='chat'),
    path('tokens/', TokenBalanceView.as_view(), name='tokens')
]