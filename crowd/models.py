from django.contrib.auth.models import User
from django.db import models
__author__ = 'sannies'


models.BooleanField(default=False,
help_text=("Crowd backed user?")).contribute_to_class(User,'isCrowdUser')