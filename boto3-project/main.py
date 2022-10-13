# -*- coding: utf-8 -*-
from os import access
import boto3
import csv
import requests
from datetime import datetime, timezone

from requests.packages.urllib3.exceptions import InsecureRequestWarning

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)

session = boto3.Session()


def utc_to_local(utc_dt):
    return utc_dt.replace(tzinfo=timezone.utc).astimezone(tz=None)


def diff_dates(date1, date2):
    return abs(date2 - date1).days


def find_iamUser_name_list():
    iam = session.client('iam', verify=False)
    userDetailList = iam.get_account_authorization_details(Filter=["User"])

    userList = []
    for user in userDetailList["UserDetailList"]:
        varname = user["UserName"]
        userList.append(varname)
    return userList


def find_iamRole_name_list():
    roleNameList = []
    client = boto3.client('iam')
    res = client.list_roles()
    for role in res['Roles']:
        roleNameList.append(role['RoleName'])

    return roleNameList


def get_user_last_password_used():
    print("--------------체크리스트 1. IAM USER 콘솔 로그인 기록--------------")
    iam = boto3.resource('iam')
    userList = find_iamUser_name_list()
    for userName in userList:
        user = iam.User(userName)
        res = user.password_last_used
        try:
            numOfDays = diff_dates(utc_to_local(datetime.utcnow()), utc_to_local(res))
        except:
            print(userName + " : 콘솔로그인 30일 경과 or 미사용(확인필요)")
        else:
            if numOfDays < 30:
                print(userName + " : 콘솔로그인 30일 이내(양호)")
            else:
                print(userName + " : 콘솔로그인 30일 경과 or 미사용(확인필요)")


def get_user_active_key_age_and_lastUsed():
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
                    print(user.user_name + " : 액세스 키[" + AccessId + "] 수명 60일 이내(양호)")
                if (Status == "Active"):
                    if KEY in LastUsed["AccessKeyLastUsed"]:
                        accessKeyLastUsed = LastUsed['AccessKeyLastUsed'][KEY]
                        numOfDays2 = diff_dates(utc_to_local(datetime.utcnow()), utc_to_local(accessKeyLastUsed))
                        if numOfDays2 < 30:
                            print(user.user_name + " : 액세스 키[" + AccessId + "] 활성화 및 30일 이내 사용함(양호)")
                        else:
                            print(user.user_name + " : 액세스 키[" + AccessId + "] 홀성화 BUT 30일 이상 사용안함(확인필요)")
                    else:
                        print(user.user_name + " : 액세스 키[" + AccessId + "] 활성화 BUT 사용한적 없음(키 불필요 삭제해야함)")
                else:
                    print(user.user_name + " : 액세스 키[" + AccessId + "] 비활성화(확인필요)")
        else:
            print(user.user_name + " : 액세스 키 없음")


def get_user_mfa():
    print("--------------체크리스트 3. IAM USER MFA 사용 확인--------------")
    client = boto3.client('iam')
    userList = find_iamUser_name_list()

    for userName in userList:
        res = client.list_mfa_devices(UserName=userName)
        print(res['MFADevices'])


def get_iamRole_lastUsed():
    print("--------------체크리스트 4. 불필요한 IAM 역할 존재 여부 확인--------------")
    client = boto3.client('iam')
    for RoleName in find_iamRole_name_list():
        res = client.get_role(RoleName=RoleName)
        data = res['Role']['RoleLastUsed']
        try:
            numOfDays = diff_dates(utc_to_local(datetime.utcnow()), utc_to_local(data['LastUsedDate']))
            if numOfDays < 30:
                print(RoleName + " : 30일 이내 사용됨")
            else:
                print(RoleName + " : 사용된지 30일이 지난 역할(불필요)")
        except:
            print(RoleName + " : 한번도 사용된 적 없음")


def get_securityGroup_list():
    cidr_block = ""
    ip_protocol = ""
    from_port = ""
    to_port = ""
    from_source = ""

    f = open('Security_Group.csv', 'w', encoding='utf-8', newline='')
    wr = csv.writer(f)

    print("%s, %s, %s, %s, %s, %s, %s" % (
    "Region", "Group-Name", "Group-ID", "In/Out", "Protocol", "Port", "Source/Destination"))

    wr.writerow(["Region", "Group-Name", "Goup-ID", "In/Out", "Protocol", "Port", "Source", "Destination"])

    regions = session.get_available_regions('ec2')

    for region in regions:
        ec2_client = boto3.client('ec2', region, verify=False)
        try:
            vpcs = ec2_client.describe_vpcs()
            sgs = ec2_client.describe_security_groups()["SecurityGroups"]

            for sg in sgs:
                group_name = sg["GroupName"]
                group_id = sg["GroupId"]
                inbound = sg["IpPermissions"]

                for rule in inbound:
                    print(group_name)
                    print(rule)
                    if rule["IpProtocol"] == "-1":

                        traffic_type = "All Traffic"
                        ip_porotocol = "ALL"
                        to_port = "ALL"
                        print(region + " --> " + group_name + " : ALL Inbound 정책 사용중 [ 취약 ]")

                    else:
                        ip_protocol = rule["IpProtocol"]
                        from_port = rule["FromPort"]
                        to_port = rule["ToPort"]
                        if to_port == -1:
                            to_port = "N/A"

                    if len(rule["IpRanges"]) > 0:
                        for ip_range in rule["IpRanges"]:
                            cidr_block = ip_range["CidrIp"]
                            if "Description" in ip_range.keys():
                                desc = ip_range["Description"]
                                wr.writerow(
                                    [region, group_name, group_id, "Inbound", ip_protocol, to_port, cidr_block, desc])
                            else:
                                wr.writerow([region, group_name, group_id, "Inbound", ip_protocol, to_port, cidr_block])

                    if len(rule["Ipv6Ranges"]) > 0:
                        for ip_range in rule["Ipv6Ranges"]:
                            cidr_block = ip_porotocol_range["CidrIpv6"]
                            if "Description" in ip_range.keys():
                                desc = ip_range["Description"]
                                wr.writerow(
                                    [region, group_name, group_id, "Inbound", ip_protocol, to_port, cidr_block, desc])
                            else:
                                wr.writerow([region, group_name, group_id, "Inbound", ip_protocol, to_port, cidr_block])

                    if len(rule["UserIdGroupPairs"]) > 0:
                        for source in rule["UserIdGroupPairs"]:
                            from_source = source["GroupId"]
                            wr.writerow([region, group_name, group_id, "Inbound", ip_protocol, to_port, from_source])

                outbound = sg["IpPermissionsEgress"]
                for rule in outbound:
                    if rule["IpProtocol"] == "-1":
                        traffic_type = "All Trafic"
                        ip_protocol = "ALL"
                        to_port = "ALL"
                    else:
                        ip_protocol = rule["IpProtocol"]
                        from_port = rule["FromPort"]
                        to_port = rule["ToPort"]
                        if to_port == -1:
                            to_port = "N/A"

                    if len(rule["IpRanges"]) > 0:
                        for ip_range in rule["IpRanges"]:
                            cidr_block = ip_range["CidrIp"]
                            if "Description" in ip_range.keys():
                                desc = ip_range["Description"]
                                wr.writerow(
                                    [region, group_name, group_id, "Outbound", ip_protocol, to_port, cidr_block, desc])
                            else:
                                wr.writerow([region, group_name, group_id, "Inbound", ip_protocol, to_port, cidr_block])

                    if len(rule["Ipv6Ranges"]) > 0:
                        for ip_range in rule["Ipv6Ranges"]:
                            cidr_block = ip_range["CidrIpv6"]
                            if "Description" in ip_range.keys():
                                desc = ip_range["Description"]
                                wr.writerow(
                                    [region, group_name, group_id, "Outbound", ip_protocol, to_port, cidr_block, desc])
                            else:
                                wr.writerow([region, group_name, group_id, "Inbound", ip_protocol, to_port, cidr_block])

                    if len(rule["UserIdGroupPairs"]) > 0:
                        for source in rule["UserIdGroupPairs"]:
                            from_source = source["GroupId"]
                            wr.writerow([region, group_name, group_id, "Outbound", ip_protocol, to_port, from_source])

        except Exception as e:
            print(region + " is Inactivated")

    f.close()

def get_s3_public_access_configure():
    client = boto3.client('s3')
    res = client.list_buckets()
    for bucket in res['Buckets']:
        try:
            public_access = client.get_public_access_block(Bucket=bucket['Name'])
            if public_access['PublicAccessBlockConfiguration']['BlockPublicAcls'] == True and \
                public_access['PublicAccessBlockConfiguration']['IgnorePublicAcls'] == True and \
                public_access['PublicAccessBlockConfiguration']['BlockPublicPolicy'] == True and \
                public_access['PublicAccessBlockConfiguration']['RestrictPublicBuckets'] == True:
                print(bucket['Name']+' : NOT public')
            else: print(bucket['Name']+' : public')
        except:
            print(bucket['Name']+' : public')

def get_s3_bucket_encryption():
    client = boto3.client('s3')
    res = client.list_buckets()
    for bucket in res['Buckets']:
        try:
            s3_encryption = client.get_bucket_encryption(Bucket=bucket['Name'])
            print(bucket['Name']+' : encryption')
        except:
            print(bucket['Name']+' : NOT encryption')



if __name__ == '__main__':
    # get_user_last_password_used()
    # print()
    # get_user_active_key_age_and_lastUsed()
    # print()
    # get_user_mfa() 미완성
    # print()
    # get_iamRole_lastUsed()
    # get_securityGroup_list()
    # get_s3_public_access_configure()
    # get_s3_bucket_encryption()
