from django.contrib.auth import get_user_model
from django.contrib.auth.models import (
    AbstractBaseUser,
    BaseUserManager,
    PermissionsMixin,
)
from django.db import models
from django.utils import timezone

# Custom user Manager Model
class UserManager(BaseUserManager):
    def create_user(self, email, password=None, **extra_fields):
        if not email:
            raise ValueError("Users must have an email address")
        user = self.model(email=self.normalize_email(email), **extra_fields)
        user.set_password(password)
        user.save(using=self._db)
        return user

    def create_superuser(self, email, password, **extra_fields):
        user = self.create_user(email, password, **extra_fields)
        user.is_superuser = True
        user.is_staff = True
        user.save(using=self._db)
        return user


# Custom user Model
class User(AbstractBaseUser, PermissionsMixin):
    email = models.EmailField(unique=True, max_length=255, null=True)
    phone = models.CharField(unique=True, max_length=255, null=True)
    name = models.CharField(max_length=50, default="Test")
    user_type = models.CharField(max_length=20, default="ananymous")
    scope = models.CharField(max_length=500, default="")
    domain = models.CharField(max_length=50, default="")
    is_active = models.BooleanField(default=True)
    is_staff = models.BooleanField(default=False)
    is_online = models.BooleanField(default=False)

    objects = UserManager()

    USERNAME_FIELD = "email"

    def get_short_name(self):
        return self.email

    def __str__(self):
        if self.email is not None:
            return self.email
        elif self.phone is not None:
            return self.phone
        else:
            return self.name


# Custome user model end


# Create a model - Domain
class Domains(models.Model):
    name = models.CharField(max_length=250, verbose_name="Domain Name")

    def __str__(self):
        return self.name


# Create a model - Services
class Services(models.Model):
    service = models.CharField(max_length=250, verbose_name="Service Name")
    did = models.ForeignKey(
        to=Domains, on_delete=models.CASCADE, verbose_name="Linked Domain Name"
    )

    def __str__(self):
        return "%s - %s" % (self.service, self.did.name)


# Create a model - Technologies
class Technologies(models.Model):
    technology = models.CharField(max_length=250, verbose_name="Technology Name")
    sid = models.ForeignKey(
        to=Services, on_delete=models.CASCADE, verbose_name="Linked Service Name"
    )

    def __str__(self):
        return "%s - %s - %s" % (self.technology, self.sid.service, self.sid.did.name)


class Categories(models.Model):
    category = models.CharField(max_length=250)
    tid = models.ForeignKey(
        to=Technologies, on_delete=models.CASCADE, verbose_name="Linked Technology Name"
    )

    def __str__(self):
        return "%s - %s - %s - %s" % (
            self.category,
            self.tid.technology,
            self.tid.sid.service,
            self.tid.sid.did.name,
        )


# Create a model - Keyword


class Keywords(models.Model):
    keyword = models.CharField(max_length=250)
    key_answer = models.TextField(default="")
    weight = models.FloatField()
    tid = models.ForeignKey(
        to=Technologies,
        on_delete=models.SET_NULL,
        null=True,
        verbose_name="Linked Technology Name",
    )

    def __str__(self):
        return "%s %f" % (self.keyword, self.weight)


# Create a model - FullLengthKeyword
class FullLengthKeyword(models.Model):
    keyword = models.CharField(max_length=500, unique=True)
    full_answer = models.TextField()

    def __str__(self):
        return self.keyword


# Create a model - GeneralKeyword
class GeneralKeyword(models.Model):
    keyword = models.CharField(max_length=500, unique=True)
    gen_answer = models.TextField()

    def __str__(self):
        return self.keyword


class StaticKeyword(models.Model):
    keyword = models.CharField(max_length=500, unique=True)

    def __str__(self):
        return self.keyword


class GramaticalKeyword(models.Model):
    keyword = models.CharField(max_length=50, unique=True)

    def __str__(self):
        return self.keyword


# Create a model - Messages
class Messages(models.Model):
    msg = models.TextField()
    time = models.TimeField(auto_now_add=True)
    aid = models.ForeignKey(Keywords, on_delete=models.SET_NULL, null=True)
    faid = models.ForeignKey(FullLengthKeyword, on_delete=models.SET_NULL, null=True)
    gaid = models.ForeignKey(GeneralKeyword, on_delete=models.SET_NULL, null=True)
    did = models.ForeignKey(Domains, on_delete=models.SET_NULL, null=True)
    sid = models.ForeignKey(Services, on_delete=models.SET_NULL, null=True)
    tid = models.ForeignKey(Technologies, on_delete=models.SET_NULL, null=True)
    cid = models.ForeignKey(Categories, on_delete=models.SET_NULL, null=True)
    uid = models.ForeignKey(User, on_delete=models.CASCADE)
    relevant = models.BooleanField()
    user = models.ForeignKey(User, related_name= 'User_messaged' ,on_delete=models.SET_NULL,null=True)
    other = models.ForeignKey(get_user_model(), related_name='they_messaged', on_delete=models.SET_NULL,null=True)
    is_read = models.BooleanField(default=False)
    
    def __str__(self):
        return self.msg


class UserInfo(models.Model):
    city = models.CharField(max_length=20, null=True)
    region = models.CharField(max_length=20, null=True)
    country = models.CharField(max_length=20, null=True)
    zipcode = models.CharField(max_length=7, null=True)
    asn = models.CharField(max_length=10, null=True)
    ipaddr = models.GenericIPAddressField(null=True)
    country_calling_code = models.CharField(max_length=5, null=True)
    latitute = models.DecimalField(max_digits=10, decimal_places=5, null=True)
    longitute = models.DecimalField(max_digits=10, decimal_places=5, null=True)
    user_name = models.CharField(max_length=15,null=True)
    user = models.OneToOneField(
        get_user_model(), on_delete=models.CASCADE, related_name="info"
    )

    def __str__(self):
        return self.user.email

#human interaction part - may 31


# class customermessage(models.Model):
#     sender = models.ForeignKey(User, on_delete=models.CASCADE)
#     receiver = models.ForeignKey(get_user_model(),  on_delete=models.CASCADE)
#     msg = models.CharField(max_length=500)
#     is_read = models.BooleanField(default=False)
#     date = models.DateTimeField(default=timezone.now)

#     def __str__(self):
#         return "{} - MESSAGED TO - {} ".format(self.sender.email , self.receiver.email )



