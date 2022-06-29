from django.utils import timezone
from datetime import datetime, timedelta
from django.db import models
from helpers.models import TrackingModels
from django.contrib.auth.validators import UnicodeUsernameValidator
from django.contrib.auth.models import (
    PermissionsMixin, UserManager, AbstractBaseUser)


class MyUserManager(UserManager):

    def _create_user(self, username, email, password, **extra_fields):
        """
        Create and save a user with the given username, email, and password.
        """
        if not username:
            raise ValueError('The given username must be set')

        if not email:
            raise ValueError('The given email must be set')

        email = self.normalize_email(email)
        username = self.model.normalize_username(username)
        user = self.model(username=username, email=email, **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_user(self, username, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', False)
        extra_fields.setdefault('is_superuser', False)
        return self._create_user(username, email, password, **extra_fields)

    def create_superuser(self, username, email, password=None, **extra_fields):
        extra_fields.setdefault('is_staff', True)
        extra_fields.setdefault('is_superuser', True)

        if extra_fields.get('is_staff') is not True:
            raise ValueError('Superuser must have is_staff=True.')
        if extra_fields.get('is_superuser') is not True:
            raise ValueError('Superuser must have is_superuser=True.')

        return self._create_user(username, email, password, **extra_fields)


class User(AbstractBaseUser, PermissionsMixin, TrackingModels):
    """
    An abstract base class implementing a fully featured User model with
    admin-compliant permissions.
    Username and password are required. Other fields are optional.
    """
    username_validator = UnicodeUsernameValidator()

    username = models.CharField(('username'),
                                max_length=150,
                                unique=True,
                                help_text=(
        'Required. 150 characters or fewer. Letters, digits and @/./+/-/_ only.'),
        validators=[username_validator],
        error_messages={
            'unique': ("A user with that username already exists."),
    },
    )
    email = models.EmailField(('email address'), blank=False, unique=True)
    is_staff = models.BooleanField(('staff status'),
                                   default=False,
                                   help_text=(
        'Designates whether the user can log into this admin site.'),
    )
    is_active = models.BooleanField(('active'),
                                    default=True,
                                    help_text=(
        'Designates whether this user should be treated as active. '
        'Unselect this instead of deleting accounts.'
    ),
    )
    date_joined = models.DateTimeField(('date joined'), default=timezone.now)
    email_verified = models.BooleanField(('email_verified'),
                                         default=False,
                                         help_text=(
        'Designates whether this users email is verified. '
    ),
    )

    objects = MyUserManager()

    EMAIL_FIELD = 'email'
    USERNAME_FIELD = 'email'
    REQUIRED_FIELDS = ['username']

    @property
    def token(self):
        token = jwt.encode(
            {'username': self.username, 'email': self.email,
                'exp': datetime.utcnow() + timedelta(hours=24)},
            settings.SECRET_KEY, algorithm='HS256')

        return token
