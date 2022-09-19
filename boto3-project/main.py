from os import access
import boto3
import requests
from datetime import datetime, timezone

from requests.packages.urllib3.exceptions import InsecureRequestWarning
requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

def utc_to_local(utc_dt):
    return utc_dt.replace(tzinfo=timezone.utc).astimezone(tz=None)

def diff_dates(date1, date2):
    return abs(date2 - date1).days

session = boto3.Session()

def find_iamUser_list():
    iam = session.client('iam', verify=False)
    userDetailList = iam.get_account_authorization_details(Filter=["User"])
    
    userList = []
    for user in userDetailList["UserDetailList"]:
        varname = user["UserName"]
        userList.append(varname)
    return userList

def get_user_lated_password_used():
    print("--------------체크리스트 1. IAM USER 콘솔 로그인 기록--------------")
    iam = boto3.resource('iam')
    userList = find_iamUser_list()
    for userName in userList:
        user = iam.User(userName)
        res = user.password_last_used
        try:
            numOfDays = diff_dates(utc_to_local(datetime.utcnow()), utc_to_local(res))
        except:
            print(userName+" : 콘솔로그인 30일 경과 or 미사용(확인필요)")
        else:
            if numOfDays < 30:
                print(userName+" : 콘솔로그인 30일 이내(양호)")
            else: print(userName+" : 콘솔로그인 30일 경과 or 미사용(확인필요)")

def get_user_active_key_age_and_used():
    print("--------------체크리스트 2. IAM USER 액세스 키 기준 준수 확인--------------")
    KEY = 'LastUsedDate'
    iam = boto3.resource('iam')
    client = boto3.client('iam')
    for user in iam.users.all():
        Metadata = client.list_access_keys(UserName=user.user_name)
        if Metadata['AccessKeyMetadata']:
            for key in user.access_keys.all():
                AccessId = key.access_key_id
                Status = key.status
                CreatedDate = key.create_date

                numOfDays = diff_dates(utc_to_local(datetime.utcnow()), utc_to_local(CreatedDate))
                LastUsed = client.get_access_key_last_used(AccessKeyId=AccessId)
                if numOfDays < 60:
                    print(user.user_name+" : 액세스 키 수명 60일 이내(양호)")
                if(Status == "Active"):
                    if KEY in LastUsed["AccessKeyLastUsed"]:
                        accessKeyLastUsed = LastUsed['AccessKeyLastUsed'][KEY]
                        numOfDays2 = diff_dates(utc_to_local(datetime.utcnow()), utc_to_local(accessKeyLastUsed))
                        if numOfDays2 < 30:
                            print(user.user_name+" : 액세스 키 활성화 및 30일 이내 사용함(양호)")
                        else: print(user.user_name+" : 액세스 키 홀성화 BUT 30일 이상 사용안함(확인필요)")
                    else: print(user.user_name+" : 액세스 키 활성화 BUT 사용한적 없음(키 불필요 삭제해야함)")
                else: print(user.user_name+" : 액세스 키 비활성화(확인필요)")
        else: print(user.user_name+" : 액세스 키 없음")


if __name__=='__main__':
    get_user_lated_password_used()
    print()
    get_user_active_key_age_and_used()
