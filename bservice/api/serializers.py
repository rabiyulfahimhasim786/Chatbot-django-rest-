from django.db import models
from django.db.models import fields
from bservice.models import (Categories, Domains, FullLengthKeyword,
                             GeneralKeyword, GramaticalKeyword, Keywords,
                             Messages, Services, StaticKeyword, Technologies,
                             UserInfo,)
from django.conf import settings
from django.contrib.auth import authenticate, get_user_model
from django.core.mail import EmailMessage
from rest_framework import serializers
from rest_framework.serializers import ModelSerializer

User = get_user_model()



def email_to(to_email):
    subject = 'Welcome to Desss Inc - Chat '
    message = ' Thanks For your information !! We will contact you as soon as possible , please contact desss office chennai!!! '
    email_from = settings.EMAIL_HOST_USER
    recipient_list = [to_email, ]
    email = EmailMessage(
        subject,
        message,
        email_from,
        recipient_list,
        # bcc=['dev@desss.com', 'vishnu@desss.com', ],
        # reply_to=['another@example.com'],
        # headers={'Message-ID': 'foo'},
    )
    email.send(fail_silently=False)
  

def email_to_dev(msg):
    subject = 'Welcome to Desss Inc - User Detail '
    message = msg
    email_from = settings.EMAIL_HOST_USER
    recipient_list = ['dev@desss.com', '7135578001@vtext.com']
    email = EmailMessage(
        subject,
        message,
        email_from,
        recipient_list,
        # cc=['vishnu@desss.com', 'gopi@desss.com'],
    )
    email.send(fail_silently=False)


# User Class serialization
class UserSerializer(ModelSerializer):
    user_name  = serializers.CharField(allow_null=True)
    class Meta:
        model = get_user_model()
        fields = ('id', 'email', 'phone', 'name', 'password',
                  'user_type', 'last_login', 'scope', 'domain','user_name','is_staff','is_online')
        extra_kwargs = {'password': {'write_only': True}}

    def create(self, validated_data):
        user = User(
            email=validated_data['email'],
            phone=validated_data['phone'],
            name=validated_data['name']
        )
        user.set_password(validated_data['password'])
        user.save()
        return user

    # def validate_phone(self, value):
    #     user = User.objects.filter(phone=value)
    #     if user:
    #         raise serializers.ValidationError("Phone no already exist")
    #     return value
    #
    # def validate_email(self, value):
    #     user = User.objects.filter(email=value)
    #     if user:
    #         raise serializers.ValidationError("Email already exist")
    #     return value


class UserUpdateSerializer(ModelSerializer):
    class Meta:
        model = get_user_model()
        fields = ('email', 'phone', 'name', 'user_type', 'scope', 'domain','is_online',)

    def update(self, instance, validated_data):
        password = validated_data.get('password', None)
        instance.email = validated_data.get('email', instance.email)
        instance.phone = validated_data.get('phone', instance.phone)
        instance.name = validated_data.get('name', instance.name)
        instance.scope = validated_data.get('scope', instance.scope)
        instance.domain = validated_data.get('domain', instance.domain)
        instance.user_type = validated_data.get('user_type', instance.user_type)
        instance.is_online = validated_data.get('is_online',instance.is_online)
        if password is not None:
            instance.set_password(password)
        instance.save()
        if '@test.com' not in instance.email:
            email_to(instance.email)
            msg = "User Name\t: {},\nEmail\t\t: {},\nphone No\t\t: {},\nmessage\t\t: {}".format(
                instance.name, instance.email, instance.phone, instance.scope)
            email_to_dev(msg)
        return instance


class UserLoginSerializer(serializers.Serializer):
    username = serializers.CharField(required=True, max_length=100)
    password = serializers.CharField(required=True, max_length=100)

    def validate(self, data):
        username = data.get("username", "")
        password = data.get("password", "")
        if username and password:
            user = authenticate(username=username, password=password)
            if user:
                if user.is_active:
                    data["user"] = user
                else:
                    msg = "User is deactivated"
                    raise serializers.ValidationError(msg)
            else:
                msg = "Unable to login with given credentials"
                raise serializers.ValidationError(msg)
        else:
            msg = "Must provide username and password both"
            raise serializers.ValidationError(msg)
        return data


class FullLengthKeywordSerializer(ModelSerializer):
    class Meta:
        model = FullLengthKeyword
        fields = '__all__'


class GeneralKeywordSerializer(ModelSerializer):
    class Meta:
        model = GeneralKeyword
        fields = '__all__'


class StaticKeywordSerializer(ModelSerializer):
    class Meta:
        model = StaticKeyword
        fields = '__all__'


class GramaticalKeywordSerializer(ModelSerializer):
    class Meta:
        model = GramaticalKeyword
        fields = '__all__'


class KeywordSerializer(ModelSerializer):
    class Meta:
        model = Keywords
        fields = ('id', 'keyword', 'key_answer', 'weight')


class DomainSerializer(ModelSerializer):
    class Meta:
        model = Domains
        fields = '__all__'


class ServiceSerializer(ModelSerializer):
    domain_name = serializers.SerializerMethodField()

    class Meta:
        model = Services
        fields = ('id', 'service', 'did', 'domain_name')

    def get_domain_name(self, obj):
        return obj.did.name


class TechnologySerializer(ModelSerializer):
    service_name = serializers.SerializerMethodField()
    domain_id = serializers.SerializerMethodField()
    domain_name = serializers.SerializerMethodField()

    class Meta:
        model = Technologies
        fields = ('id', 'technology', 'sid', 'service_name', 'domain_id', 'domain_name')

    def get_service_name(self, obj):
        return obj.sid.service

    def get_domain_name(self, obj):
        return obj.sid.did.name

    def get_domain_id(self, obj):
        return obj.sid.did.id


class CategorySerializer(ModelSerializer):
    tech_name = serializers.SerializerMethodField()
    service_id = serializers.SerializerMethodField()
    service_name = serializers.SerializerMethodField()
    domain_id = serializers.SerializerMethodField()
    domain_name = serializers.SerializerMethodField()
    
    class Meta:
        model = Categories
        fields = ('id', 'category', 'tid', 'tech_name', 'service_id',
                  'service_name', 'domain_id', 'domain_name')

    def get_tech_name(self, obj):
        return obj.tid.technology

    def get_service_name(self, obj):
        return obj.tid.sid.service

    def get_service_id(self, obj):
        return obj.tid.sid.id

    def get_domain_name(self, obj):
        return obj.tid.sid.did.name

    def get_domain_id(self, obj):
        return obj.tid.sid.did.id


class MessageSerializer(ModelSerializer):
    user_email = serializers.SerializerMethodField()
    user_phone = serializers.SerializerMethodField()
    last_login = serializers.SerializerMethodField()
    user_name = serializers.SerializerMethodField()
    key_answer = serializers.SerializerMethodField()
    gen_answer = serializers.SerializerMethodField()
    full_answer = serializers.SerializerMethodField()
    domain = serializers.SerializerMethodField()
    service = serializers.SerializerMethodField()
    tech = serializers.SerializerMethodField()
    scope = serializers.SerializerMethodField()
    u_domain = serializers.SerializerMethodField()

    class Meta:
        model = Messages
        fields = ('id', 'time', 'uid', 'user_email', 'user_phone', 'user_name', 'last_login',
                  'scope', 'u_domain', 'msg', 'aid', 'key_answer', 'gaid', 'gen_answer',  'faid',
                  'full_answer', 'did', 'domain', 'sid', 'service', 'tid', 'tech', 'relevant', 'cid','user','other','is_read')

    def get_user_phone(self, obj):
        return obj.uid.phone

    def get_last_login(self, obj):
        return obj.uid.last_login

    def get_user_email(self, obj):
        return obj.uid.email

    def get_user_name(self, obj):
        return obj.uid.name

    def get_key_answer(self, obj):
        if obj.aid is None:
            return None
        return obj.aid.key_answer

    def get_full_answer(self, obj):
        if obj.faid is None:
            return None
        return obj.faid.full_answer

    def get_gen_answer(self, obj):
        if obj.gaid is None:
            return None
        return obj.gaid.gen_answer

    def get_domain(self, obj):
        if obj.did is None:
            return None
        return obj.did.name

    def get_service(self, obj):
        if obj.sid is None:
            return None
        return obj.sid.service

    def get_tech(self, obj):
        if obj.tid is None:
            return None
        return obj.tid.technology

    def get_scope(self, obj):
        return obj.uid.scope

    def get_u_domain(self, obj):
        return obj.uid.domain


class UserInfoSerializer(ModelSerializer):
    class Meta:
        model = UserInfo
        fields = '__all__'

    # def update(self, instance, validated_data):
    #     instance.asn = validated_data.get('asn', instance.asn)
    #     instance.city = validated_data.get('city', instance.city)
    #     instance.country = validated_data.get('country', instance.country)
    #     instance.country_calling_code = validated_data.get(
    #         'country_calling_code', instance.country_calling_code)
    #     instance.ipaddr = validated_data.get('ipaddr', instance.ipaddr)
    #     instance.latitute = validated_data.get('latitute', instance.latitute)
    #     instance.longitute = validated_data.get('longitute', instance.longitute)
    #     instance.region = validated_data.get("region", instance.region)
    #     instance.user = instance.user
    #     instance.save()
    #     return instance


# class customermessageserializer(serializers.ModelSerializer):
#     class Meta:
#         model = customermessage
#         fields = '__all__'

from django.contrib.auth.signals import user_logged_in, user_logged_out
from django.dispatch import receiver 


class adminserailzer(serializers.Serializer):
    class Meta:
        model = get_user_model()
        fields = 'is_staff'


class humaninteractionSerializer(ModelSerializer):
    user_email = serializers.SerializerMethodField()
    user_phone = serializers.SerializerMethodField()
    last_login = serializers.SerializerMethodField()
    user_name = serializers.SerializerMethodField()
    
    class Meta:
        model = Messages
        fields = ('id', 'time', 'uid', 'user_email', 'user_phone', 'user_name', 'last_login','msg','relevant','user','other','is_read')

    def get_user_phone(self, obj):
        return obj.uid.phone

    def get_last_login(self, obj):
        return obj.uid.last_login

    def get_user_email(self, obj):
        return obj.uid.email

    def get_user_name(self, obj):
        return obj.uid.name
