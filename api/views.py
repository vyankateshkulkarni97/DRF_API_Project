from django.shortcuts import render

# Create your views here.
from rest_framework import generics, permissions
from .models import User, Profile
from .serializers import UserSerializer, ProfileSerializer
from .permissions import IsAdmin, IsSolutionProvider, IsSolutionSeeker

from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.shortcuts import get_current_site
from django.core.mail import EmailMessage
from django.template.loader import render_to_string
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.utils.encoding import force_bytes, force_text
from rest_framework import generics, permissions, status
from rest_framework.response import Response
from rest_framework.views import APIView


# register/create/ the New user and all permission are different

class UserRegisterView(generics.CreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.AllowAny]

    def get_object(self):
        return self.request.user
    
    def get_permissions(self, action):
        self.action = self.get_object
        permission_classes = []
        if self.action == 'create':
            permission_classes = [IsAdmin]
        elif self.action == 'list':
            permission_classes = [IsSolutionProvider]
        elif self.action == 'retrieve' or self.action == 'update' or self.action == 'partial_update':
            permission_classes = [IsSolutionSeeker]
        elif self.action == 'destroy':
            permission_classes = [IsSolutionSeeker]
        return [permission() for permission in permission_classes]

# Login the New user , admin , seeker , provider 

class UserLoginView(generics.GenericAPIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        username = request.data.get('username')
        password = request.data.get('password')
        user = authenticate(request, username=username, password=password)
        if user:
            login(request, user)
            serializer = UserSerializer(user)
            return Response(serializer.data)
        return Response({'detail': 'Invalid credentials'}, status=status.HTTP_401_UNAUTHORIZED)

# change password for the New user , admin , seeker , provider

class UserChangePasswordView(generics.UpdateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        return self.request.user

    def update(self, request, *args, **kwargs):
        self.object = self.get_object()
        serializer = self.get_serializer(data=request.data)
        if serializer.is_valid():
            old_password = serializer.data.get('old_password')
            new_password = serializer.data.get('new_password')
            if self.object.check_password(old_password):
                self.object.set_password(new_password)
                self.object.save()
                return Response({'detail': 'Password updated successfully'})
            else:
                return Response({'detail': 'Invalid old password'}, status=status.HTTP_400_BAD_REQUEST)
        return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)

# forgot password for the  user , admin , seeker , provider

class UserForgotPasswordView(generics.GenericAPIView):
    permission_classes = [permissions.AllowAny]

    def post(self, request):
        email = request.data.get('email')
        try:
            user = User.objects.get(email=email)
        except User.DoesNotExist:
            return Response({'detail': 'No user found with the provided email'}, status=status.HTTP_404_NOT_FOUND)

        token = default_token_generator.make_token(user)
        uid = urlsafe_base64_encode(force_bytes(user.pk))
        current_site = get_current_site(request)
        mail_subject = 'Reset your password'
        message = render_to_string(
            'api/reset_password_email.html',
            {
                'user': user,
                'domain': current_site.domain,
                'uid': uid,
                'token': token,
            }
        )
        email = EmailMessage(mail_subject, message, to=[email])
        email.send()

        return Response({'detail': 'Password reset link sent to your email'})

# user profile update 

class UserProfileView(generics.RetrieveUpdateAPIView):
    queryset = Profile.objects.all()
    serializer_class = ProfileSerializer
    permission_classes = [permissions.IsAuthenticated]

    def get_object(self):
        return self.request.user.profile
    
    def update(self, request, *args, **kwargs):
        partial = kwargs.pop('partial', False)
        self.object = self.get_object()
        serializer = self.get_serializer(self.object, data=request.data, partial=partial)
        serializer.is_valid(raise_exception=True)
        self.perform_update(serializer)
        return Response(serializer.data)
