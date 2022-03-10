# import json

from django.db.models import query
from django.db.models.fields.related import RECURSIVE_RELATIONSHIP_CONSTANT
import requests as req
from django.contrib.auth.signals import user_logged_in, user_logged_out
from django.dispatch import receiver 
from rest_framework import permissions
from bservice.models import (Categories, Domains, FullLengthKeyword,
                             GeneralKeyword, GramaticalKeyword, Keywords,
                             Messages, Services, StaticKeyword, Technologies,
                             UserInfo, )
from django.contrib.auth import get_user_model, login, logout
from django.shortcuts import get_object_or_404, render
from rest_framework import filters
from rest_framework.decorators import api_view, permission_classes
from rest_framework.generics import (ListCreateAPIView,
                                     RetrieveUpdateDestroyAPIView)
from rest_framework.permissions import (AllowAny, IsAuthenticated,
                                        IsAuthenticatedOrReadOnly)
from rest_framework.response import Response
from rest_framework.status import (HTTP_200_OK, HTTP_204_NO_CONTENT,
                                   HTTP_400_BAD_REQUEST)
from rest_framework.views import APIView
from rest_framework_jwt.settings import api_settings
from rest_framework.authtoken.models import Token

from .permissions import IsAdminUserOrReadOnly, IsAllowedToWrite
# from rest_framework import serializers
from .serializers import (CategorySerializer, DomainSerializer,
                          FullLengthKeywordSerializer,
                          GeneralKeywordSerializer,
                          GramaticalKeywordSerializer, KeywordSerializer,
                          MessageSerializer, ServiceSerializer,
                          StaticKeywordSerializer, TechnologySerializer,
                          UserInfoSerializer, UserLoginSerializer,
                          UserSerializer, UserUpdateSerializer, adminserailzer, humaninteractionSerializer, )

# from django.db.models import Q

User = get_user_model()
# jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
# jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER
# jwt_decode_handler = api_settings.JWT_DECODE_HANDLER
# jwt_get_username_from_payload = api_settings.JWT_PAYLOAD_GET_USERNAME_HANDLER


class UserListCreateView(ListCreateAPIView):
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = (AllowAny,)
    filter_backends = (filters.SearchFilter,)
    search_fields = ('email', 'name', )

    def post(self, request, format='json'):
        errors = []
        existing_user = request.query_params.get("user")
        serializer = UserSerializer(data=request.data)
        if serializer.is_valid():
            user = serializer.save()
            if user:
                # payload = jwt_payload_handler(user)
                # token = jwt_encode_handler(payload)
                token , created = Token.objects.get_or_create(user = user)
                data = {'id': user.id, 'token': token.key}
                return Response({"status": data})
        # status = status.HTTP_400_BAD_REQUEST)

        for error, values in serializer.errors.items():
            errors.append(values[0])

        if errors[0] == "user with this email already exists." or errors[0] == "user with this phone already exists.":
            username = request.data.get('email', None)
            phone = request.data.get('phone', None)
            queryset = User.objects.all()
            user_eamil = queryset.filter(email=username).first()
            user_phone = queryset.filter(phone=phone).first()
            uexist = queryset.filter(id=existing_user).first()
            if user_eamil is not None or user_phone is not None:
                user = user_eamil if user_eamil else user_phone
                if uexist:
                    msgs = Messages.objects.filter(uid=uexist)
                    for msg in msgs:
                        msg.uid = user
                        msg.save()
                # payload = jwt_payload_handler(user)
                # token = jwt_encode_handler(payload)
                token , created = Token.objects.get_or_create(user = user)
                data = {'id': user.id, 'token': token.key, 'user': 'exist'}
                return Response({"status": data})
            return Response({"status": errors[0]})
        return Response({"status": serializer.errors})

    def get_queryset(self):
        queryset = User.objects.all()
        queryset = queryset.order_by("last_login")  # last_login
        return queryset


class UserRetrieveUpdateDeleteView(RetrieveUpdateDestroyAPIView):
    queryset = get_user_model().objects.all()
    serializer_class = UserUpdateSerializer
    permission_classes = (IsAuthenticatedOrReadOnly,)
    filter_backends = (filters.SearchFilter,)
    search_fields = ('email', 'name', )


class UserDeleteView(APIView):
    queryset = get_user_model().objects.all()
    serializer_class = UserUpdateSerializer
    permission_classes = (IsAuthenticatedOrReadOnly,)

    def post(self, request, format='json'):
        queryset = User.objects.all()
        users = queryset.filter(email__icontains='@test.com')
        for user in users:
            user.delete()
        return Response("Delete successful")


class UserLoginView(APIView):
    permission_classes = (AllowAny,)
    serializer_class = UserLoginSerializer
    permission_classes = (AllowAny,)

   

    def post(self, request, *args, **kwargs):
        serializer = UserLoginSerializer(data=request.data)
        if serializer.is_valid(raise_exception=True):
            user = serializer.validated_data["user"]
            print(user)
            login(request, user)
            # jwt_payload_handler = api_settings.JWT_PAYLOAD_HANDLER
            # jwt_encode_handler = api_settings.JWT_ENCODE_HANDLER
            # payload = jwt_payload_handler(user)
            # token = jwt_encode_handler(payload)
            token , created = Token.objects.get_or_create(user = user)
            data = {"token": token.key, "status": True,}
            return Response(data, status=HTTP_200_OK)
        return Response(serializer.error, status=HTTP_400_BAD_REQUEST)

   

   


class UserLogoutView(APIView):
    permission_classes = (IsAuthenticatedOrReadOnly,)

    def get(self, request):
        logout(request)
        return Response(status=HTTP_204_NO_CONTENT)



class KeywordListCreateView(ListCreateAPIView):
    queryset = Keywords.objects.all()
    serializer_class = KeywordSerializer
    permission_classes = (IsAdminUserOrReadOnly,)
    # filter_backends = (filters.SearchFilter,)
    # search_fields = ('keyword',)

    def get_queryset(self):
        queryset = Keywords.objects.all()
        query = self.request.query_params.get('q')
        if query is not None:
            li = list(query.split(','))
            count = 0
            # qs_old = Keywords.objects.none()
            if count == 0:
                q = li.pop(0)
                qs_new = queryset.filter(keyword__iexact=q.strip())
                qs_res = qs_new
            if qs_res.count() == 0:
                for q in li:
                    print(q)
                    qs_new = queryset.filter(keyword__iexact=q.strip())
                    if count != 0 and qs_new.count() != 0 and qs_res.count() != 0:
                        if qs_new[0].weight > qs_res[0].weight:
                            qs_res = qs_new
                    elif count != 0 and qs_new.count() != 0 and qs_res.count() != 0:
                        if qs_new[0].weight < qs_res[0].weight:
                            qs_res = qs_res
                    else:
                        qs_res = qs_new
                    print(qs_res)
                    count = count + 1
            return qs_res
        return queryset


class KeywordRetrieveUpdateDeleteView(RetrieveUpdateDestroyAPIView):
    queryset = Keywords.objects.all()
    serializer_class = KeywordSerializer
    permission_classes = (IsAdminUserOrReadOnly,)
    # filter_backends = (filters.SearchFilter,)
    # search_fields = ('keyword', )


class FullLengthKeywordListCreateView(ListCreateAPIView):
    queryset = FullLengthKeyword.objects.all()
    serializer_class = FullLengthKeywordSerializer
    permission_classes = (IsAdminUserOrReadOnly,)
    # filter_backends = (filters.SearchFilter,)
    # search_fields = ('keyword',)


class FullLengthKeywordRetrieveUpdateDeleteView(RetrieveUpdateDestroyAPIView):
    queryset = FullLengthKeyword.objects.all()
    serializer_class = FullLengthKeywordSerializer
    permission_classes = (IsAdminUserOrReadOnly,)
    # filter_backends = (filters.SearchFilter,)
    # search_fields = ('keyword', )


class GeneralKeywordListCreateView(ListCreateAPIView):
    queryset = GeneralKeyword.objects.all()
    serializer_class = GeneralKeywordSerializer
    permission_classes = (IsAdminUserOrReadOnly,)
    # filter_backends = (filters.SearchFilter,)
    # search_fields = ('keyword',)


class GeneralKeywordRetrieveUpdateDeleteView(RetrieveUpdateDestroyAPIView):
    queryset = GeneralKeyword.objects.all()
    serializer_class = GeneralKeywordSerializer
    permission_classes = (IsAdminUserOrReadOnly,)
    # filter_backends = (filters.SearchFilter,)
    # search_fields = ('keyword', )


class StaticKeywordListCreateView(ListCreateAPIView):
    queryset = StaticKeyword.objects.all()
    serializer_class = StaticKeywordSerializer
    permission_classes = (IsAdminUserOrReadOnly,)
    # filter_backends = (filters.SearchFilter,)
    # search_fields = ('keyword',)


class StaticKeywordRetrieveUpdateDeleteView(RetrieveUpdateDestroyAPIView):
    queryset = StaticKeyword.objects.all()
    serializer_class = StaticKeywordSerializer
    permission_classes = (IsAdminUserOrReadOnly,)
    # filter_backends = (filters.SearchFilter,)
    # search_fields = ('keyword', )


class GramaticalKeywordListCreateView(ListCreateAPIView):
    queryset = GramaticalKeyword.objects.all()
    serializer_class = GramaticalKeywordSerializer
    permission_classes = (IsAdminUserOrReadOnly,)
    # filter_backends = (filters.SearchFilter,)
    # search_fields = ('keyword',)


class GramaticalKeywordRetrieveUpdateDeleteView(RetrieveUpdateDestroyAPIView):
    queryset = GramaticalKeyword.objects.all()
    serializer_class = GramaticalKeywordSerializer
    permission_classes = (IsAdminUserOrReadOnly,)
    # filter_backends = (filters.SearchFilter,)
    # search_fields = ('keyword',)


class DomainListCreateView(ListCreateAPIView):
    queryset = Domains.objects.all()
    serializer_class = DomainSerializer
    permission_classes = (IsAdminUserOrReadOnly,)
    # filter_backends = (filters.SearchFilter,)
    # search_fields = ('name', )

    def get_queryset(self):
        queryset = Domains.objects.all()
        query = self.request.query_params.get('q')
        print(query)
        if query is not None:
            queryset = queryset.filter(name=query)
        return queryset


class DomainRetrieveUpdateDeleteView(RetrieveUpdateDestroyAPIView):
    queryset = Domains.objects.all()
    serializer_class = DomainSerializer
    permission_classes = (IsAdminUserOrReadOnly,)
    # filter_backends = (filters.SearchFilter,)
    # search_fields = ('name', )

    def retrieve(self, request, pk=None):
        queryset = Domains.objects.all()
        instance = get_object_or_404(queryset, pk=pk)
        serializer = DomainSerializer(instance)
        return Response(serializer.data)


class ServiceListCreateView(ListCreateAPIView):
    queryset = Services.objects.all()
    serializer_class = ServiceSerializer
    permission_classes = (IsAdminUserOrReadOnly,)
    filter_backends = (filters.SearchFilter,)
    search_fields = ('did__id', )

    def get_queryset(self):
        queryset = Services.objects.all()
        query = self.request.query_params.get('q')
        print(query)
        if query is not None:
            queryset = queryset.filter(service=query)
        return queryset


class ServiceRetrieveUpdateDeleteView(RetrieveUpdateDestroyAPIView):
    queryset = Services.objects.all()
    serializer_class = ServiceSerializer
    permission_classes = (IsAdminUserOrReadOnly,)
    # filter_backends = (filters.SearchFilter,)
    # search_fields = ('did__id', )


class TechnologyListCreateView(ListCreateAPIView):
    queryset = Technologies.objects.all()
    serializer_class = TechnologySerializer
    permission_classes = (IsAdminUserOrReadOnly,)
    filter_backends = (filters.SearchFilter,)
    search_fields = ('sid__id', )

    def get_queryset(self):
        queryset = Technologies.objects.all()
        query = self.request.query_params.get('q')
        print(query)
        if query is not None:
            queryset = queryset.filter(technology=query)
        return queryset


class TechnologyRetrieveUpdateDeleteView(RetrieveUpdateDestroyAPIView):
    queryset = Technologies.objects.all()
    serializer_class = TechnologySerializer
    permission_classes = (IsAdminUserOrReadOnly,)
    # filter_backends = (filters.SearchFilter,)
    # search_fields = ('technology', )


class CategoryListCreateView(ListCreateAPIView):
    queryset = Categories.objects.all()
    serializer_class = CategorySerializer
    permission_classes = (IsAdminUserOrReadOnly,)
    filter_backends = (filters.SearchFilter,)
    search_fields = ('tid__id', )

    # def get_queryset(self):
    #     queryset = Categories.objects.all()
    #     query = self.request.query_params.get('q')
    #     print(query)
    #     if query is not None:
    #         queryset = queryset.filter(catogry=query)
    #     return queryset


class CategoryRetrieveUpdateDeleteView(RetrieveUpdateDestroyAPIView):
    queryset = Categories.objects.all()
    serializer_class = CategorySerializer
    permission_classes = (IsAdminUserOrReadOnly,)


def data_slice(record, count):
    num = 25
    if count is not None:
        count = int(count)
        if count == 0:
            return record[:num]
        else:
            return record[count * num:(count + 1) * num]
    return record


#updated order by for chatbot screen
class MessageListCreateView(ListCreateAPIView):
    queryset = Messages.objects.all()
    serializer_class = MessageSerializer
    permission_classes = (IsAllowedToWrite,)
    filter_backends = (filters.SearchFilter,)
    search_fields = ('uid__id', )


class MessageRetrieveUpdateDeleteView(RetrieveUpdateDestroyAPIView):
    queryset = Messages.objects.all()
    serializer_class = MessageSerializer
    permission_classes = (IsAllowedToWrite,)
    # filter_backends = (filters.SearchFilter,)
    # search_fields = ('msg', )


class UserInfoListCreateView(ListCreateAPIView):
    queryset = UserInfo.objects.all()
    serializer_class = UserInfoSerializer
    permission_classes = [IsAuthenticated]

    def get_queryset(self):
        userinfo = UserInfo.objects.all()
        query = self.request.query_params.get('q')
        if query is not None:
            return userinfo.filter(user=query)
        return userinfo

    def get(self, request, *args, **kwargs):
        userinfo = self.get_queryset()
        serializer = UserInfoSerializer(userinfo, many=True)
        return Response(serializer.data)


class UserInfoRetrieveUpdateDeleteView(RetrieveUpdateDestroyAPIView):
    queryset = UserInfo.objects.all()
    serializer_class = UserInfoSerializer
    permission_classes = [IsAuthenticated]

    # def get_queryset(self):
    #     query = self.request.query_params.get('q')
    #     print(query)
    #     return UserInfo.objects.filter(id=query)
    #
    # def put(self, request, pk):
    #     print("working")
    #     queryset = self.get_queryset()
    #     print(queryset)
    #     instance = queryset.first()
    #     print(instance)
    #     serializer = UserInfoSerializer(instance, data=request.data)
    #     print("working")
    #     if serializer.is_valid():
    #         serializer.save()
    #         return Response(serializer.data)
    #     return Response(serializer.errors)


@api_view(['GET'])
@permission_classes((IsAdminUserOrReadOnly, ))
def keyword_list(request):
    query = request.query_params.get('q')
    qs_res = []
    count = 0
    if query is not None:
        query_list = list(query.split(','))
        q = query_list[0]
        print(q)
        qs_general = GeneralKeyword.objects.all()
        qs_new = qs_general.filter(keyword__iexact=q.strip())
        qs_res = qs_new
        if qs_res.count() != 0:
            print("general", qs_res)
            serializer = GeneralKeywordSerializer(qs_res, many=True)
            return Response({"data": serializer.data, "type": "gen"})
        qs_full = FullLengthKeyword.objects.all()
        qs_new = qs_full.filter(keyword__iexact=q.strip())
        qs_res = qs_new
        if qs_res.count() != 0:
            print("full length", qs_res)
            serializer = FullLengthKeywordSerializer(qs_res, many=True)
            return Response({"data": serializer.data, "type": "full"})
        queryset = Keywords.objects.all()
        for q in query_list:
            print(q)
            qs_new = queryset.filter(keyword__icontains=q.strip()).order_by('-weight')
            if qs_new.count() != 0 and qs_res.count() != 0:
                if qs_new[0].weight > qs_res[0].weight:
                    qs_res = qs_new
                    print("test1")
            elif qs_new.count() != 0 and qs_res.count() != 0:
                if qs_new[0].weight < qs_res[0].weight:
                    qs_res = qs_res
                    print("test2")
            elif qs_res.count() == 0:
                qs_res = qs_new
                print("test3")
            elif count == 0:
                qs_res = qs_new
                print("test4")
            count = count + 1
            print(qs_new)
            print(qs_res)
        serializer = KeywordSerializer(qs_res, many=True)
        return Response({"data": serializer.data, "type": "key"})
    return Response("No Data Founded")


@api_view(['GET', ])
@permission_classes((IsAdminUserOrReadOnly, ))
def get_weights(request):
    count = 0
    query = request.query_params.get('q')
    if '.' in query:
        query = float(query)
    else:
        query = int(query)
    low, high = query, query
    print(low, high)
    queryset = Keywords.objects.all()
    while True:
        low = low - count
        qs_low = queryset.filter(weight=low)
        if qs_low.count() == 0:
            break
        count = count + 1
    count = 0
    while True:
        high = high + count
        qs_low = queryset.filter(weight=high)
        if qs_low.count() == 0:
            break
        count = count + 1
    return Response({"low": low, "high": high})
    # low = queryset.filter(weight__lte=query).order_by('-weight').first()
    # low_ser = KeywordSerializer(low)
    # print(low)
    # high = queryset.filter(weight__gte=query).order_by('weight').first()
    # high_ser = KeywordSerializer(high)
    # print(high)
    # return Response({"low": low_ser.data, "high": high_ser.data})


@api_view(['post'])
@permission_classes([IsAuthenticated])
def desss_service_keywords(request):
    # data = request.data
    # print(data.get('data'))
    # print(request.data)
    url = 'https://chatbot.desss.com/chat_bot_api.php?action=service'
    res = req.get(url)
    if res.status_code == 200:
        data = res.json()
        lists = data.get('data')
        for list in lists:
            # First Service
            first_service = list.get('first_service')
            # print(first_service.get('title'))
            try:
                domain = Domains.objects.get(name__iexact=first_service.get('title'))
                # print("Domain :", domain)
            except Domains.DoesNotExist:
                domain = Domains.objects.create(name=first_service.get('title'))

            # Second Service
            second_service = first_service.get('second_service')
            # print("  -->", second_service.get('title'))
            try:
                service = Services.objects.get(
                    service__iexact=second_service.get('title'), did=domain)
                # print("Service :", service)
            except Services.DoesNotExist:
                service = Services.objects.create(service=second_service.get('title'), did=domain)

            # Third Service
            third_service = second_service.get('third_service')
            # print("    -->", third_service.get('title'))
            try:
                tech = Technologies.objects.get(
                    technology__iexact=third_service.get('title'), sid=service)
                print("Technology :", tech)
            except Technologies.DoesNotExist:
                tech = Technologies.objects.create(
                    technology=third_service.get('title'), sid=service)

            fourth_service = third_service.get('fourth_service')
            fdatas = fourth_service.get('data')
            for fdata in fdatas:
                if fdata != '':
                    # print("      -->", fdata)
                    try:
                        category = Categories.objects.get(category__iexact=fdata, tid=tech)
                        # print("Category :", category)
                    except Categories.DoesNotExist:
                        Categories.objects.create(category=fdata, tid=tech)
        return Response("success")
    return Response("failure")


@api_view(['GET', ])
@permission_classes((IsAdminUserOrReadOnly, ))
def get_services(request):
    query = request.query_params.get('q')
    tqs = Technologies.objects.none()
    cqs = Categories.objects.none()
    r_qs = []
    dist = list()
    if query is not None:
        squeryset = Services.objects.all()
        tqueryset = Technologies.objects.all()
        cqueryset = Categories.objects.all()

        service = squeryset.filter(service__icontains=query)
        if service is not None and service.count() > 0:
            for s in service:
                tech_qs = tqueryset.filter(sid=s.id)
                tqs = tqs.union(tech_qs)
            for q in tqs:
                if q.technology.lower().strip() not in dist:
                    dist.append(q.technology.lower().strip())
                    r_qs.append(q)
            serializer = TechnologySerializer(r_qs, many=True)
            return Response({"level": "2", "data": serializer.data})

        technology = tqueryset.filter(technology__icontains=query)
        if technology is not None and technology.count() > 0:
            for t in technology:
                cate_qs = cqueryset.filter(tid=t.id)
                cqs = cqs.union(cate_qs)
            for q in cqs:
                if q.category.lower().strip() not in dist:
                    dist.append(q.category.lower().strip())
                    r_qs.append(q)
            serializer = CategorySerializer(r_qs, many=True)
            return Response({"level": "3", "data": serializer.data})
    return Response({"level": "-1", "data": None})


# @api_view(['GET',])
# @permission_classes
def data_slice(record, count):
    num = 25
    if count is not None:
        count = int(count)
        if count == 0:
            return record[:num]
        else:
            return record[count * num:(count + 1) * num]
    return record

def get_key(obj):
    return obj.id


#VIEWS FOR HUMAN INTERACTION  - - 30/7/21


class humaninteractionapiView(ListCreateAPIView):
    queryset = Messages.objects.all()
    serializer_class = humaninteractionSerializer
    permission_classes = [IsAuthenticated]

    def get_msg_between_user_and_other(self, queryset, user, other):
        user_qs = queryset.filter(user=user, other=other)
        other_qs = queryset.filter(user=other, other=user)
        data = user_qs.union(other_qs).order_by('-id')
        return data

    def get(self, request):
        unique, queryset_list = [], []
        msg_count = {}
        # is_premium_only_can = {}
        list = self.request.query_params.get('q')
        user = self.request.query_params.get('user')
        other = self.request.query_params.get('other')
        count = request.query_params.get('count', None)

        queryset = Messages.objects.all()
        

        # List the message as list based on user
        if list == "list" and queryset is not None:
            # To whome i had sent a message
            userlist = queryset.filter(user=self.request.user).order_by('-id')

            # Who are they sent message to me
            queryset_user = queryset.filter(
                other=self.request.user).order_by('-id')
            queryset_o = queryset_user.exclude(
                user=self.request.user).order_by('-id')

            for q in queryset_o:
                if q.user.id not in unique:
                    unique.append(q.user.id)
                    last_msg = self.get_msg_between_user_and_other(
                        queryset, q.user, q.other)

                    queryset_list.append(last_msg[0])
                    # Messaage Count based on user
                    # qs = last_msg.filter(user=q.user.id)  # .filter(is_read=False)
                    msg_count[q.user.id] = queryset_o.filter(
                        user=q.user.id).filter(is_read=False).count()
                    # is_friend[q.user.id] = self.check_is_friend_or_not(friend_qs, q.user, q.other)

            for q in userlist:
                if q.other.id not in unique:
                    unique.append(q.other.id)
                    last_msg = self.get_msg_between_user_and_other(
                        queryset, q.user, q.other)
                    queryset_list.append(last_msg[0])
                    # Messaage Count based on user
                    # last_msg.filter(other=q.other.id).count()
                    msg_count[q.other.id] = 0
                    # is_friend[q.other.id] = self.check_is_friend_or_not(friend_qs, q.user, q.other)

            for key in msg_count:
                data = sorted(queryset_list, key=get_key)
            serializer = MessageSerializer(data_slice(data, count), many=True)
            return Response({
                "data": serializer.data,
                "count": msg_count,
            })

        # Chat between two users
        if user is not None and other is not None:
            # char perpose changed to user to other and other to user
            # user_qs = queryset.filter(user=user, other=other)
            other_qs = queryset.filter(user=other, other=user)
            data = self.get_msg_between_user_and_other(queryset, user, other)
            # print(user_blocked)
            # Mark unreaded message into readed
            for d in other_qs:
                if d.is_read is False:
                    d.is_read = True
                    d.save()
            # Serialize the queryset and send the response
            serializer = MessageSerializer(data_slice(data, count), many=True)
            return Response({"data": serializer.data,})

        serializer = MessageSerializer(queryset, many=True)
        return Response({"data": serializer.data})

    def post(self, request, *args, **kwargs):
        user = request.data.get('user', None)
        other = request.data.get('other', None)
        msg = self.request.query_params.get('msg')
        u = User.objects.get(id=user)
        serializer = MessageSerializer(data=request.data)
        if serializer.is_valid():
            serializer.save()
            return Response({"status": "success"})
        return Response({"status": "Something went wrong"})


class humaninteractionmessageupdate(RetrieveUpdateDestroyAPIView):
    queryset = Messages.objects.all()
    serializer_class = humaninteractionSerializer
    permission_classes = (IsAllowedToWrite,)

	
from rest_framework import generics

class adminloginstatuscode(generics.RetrieveAPIView):
    permission_classes = [AllowAny]
    queryset = User.objects.all()
    serializer_class = adminserailzer


    def get(self,request):
        user = User.objects.filter(is_staff=True)
        serializer = self.get_serializer(request.user)
        return Response(serializer.data)
        
                
def error_404_view(request,exception):
    return render(request,'404.html')
       

# update to admin login status in userupdateview-api
#DRIVE CODE FOR IS_ONLINE (admin user online status) -- 

from django.contrib.auth.signals import user_logged_in, user_logged_out
from django.dispatch import receiver 


@receiver(user_logged_in)
def got_online(sender, user, request, **kwargs):    
    if request.user.is_authenticated and request.user.is_staff:
        user.is_online = True
        user.save()
        print("admin login success 200")
        return user
        

@receiver(user_logged_out)
def got_offline(sender, user, request, **kwargs):   
    if request.user.is_authenticated and request.user.is_staff:
        user.is_online = False
        user.save()
        print("admin logout success , 302 --> 200 ok ")
        return user
        

def index(request):
    return render(request,'index.html')