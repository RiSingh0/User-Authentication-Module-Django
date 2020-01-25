from django.db import models
from django.contrib.auth.models import User
import uuid
import os


def get_file_path(instance, filename):
    ext = filename.split('.')[-1]
    filename = "%s.%s" % (uuid.uuid4(), ext)
    return os.path.join('profile_pics', filename)


class UserProfileInfo(models.Model):
    google_id=models.CharField(max_length=100,blank=True)
    user = models.OneToOneField(User,on_delete=models.CASCADE)
    Gender = models.CharField(max_length=10,default='')
    profile_pic = models.ImageField(upload_to=get_file_path,blank=True)
    def __str__(self):
      return self.user.username