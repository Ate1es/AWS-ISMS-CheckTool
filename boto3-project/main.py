import boto3
from boto3 import Session

def main():
    print("[*] This is ISMS-P Auto testing Tool [*]")
   # global region_name
   # region_name = str(input("input your region : "))
   # print(region_name)
    
def check_account_password_policy(response):
    if response["PasswordPolicy"]["MinimumPasswordLength"] < 8:
        return False
    elif response["PasswordPolicy"]["MinimumPasswordLength"] <10:
        if response["PasswordPolicy"]["RequireNumbers"] == False or response["PasswordPolicy"]["RequireLowercaseCharacters"] == False or response["PasswordPolicy"]["RequireSymbols"] == False:
            return False
        else : return True
    else :
        check_cnt = 0
        if response["PasswordPolicy"]["RequireNumbers"] == True:
            check_cnt += 1
        if response["PasswordPolicy"]["RequireSymbols"] == True:
            check_cnt += 1
        if response["PasswordPolicy"]["RequireLowercaseCharacters"] == True:
            check_cnt += 1
        if check_cnt < 2:
            return False
        else : return True
        

def get_account_password_policy():
    client = boto3.client('iam')
    response = client.get_account_password_policy()
    result = check_account_password_policy(response)
    print(result)

# paginate 를 username 변수 없이 호출했을 때 액세스 키가 리턴되면  루트 액세스 키
def check_access_key():
    client = boto3.client('iam')
    paginator = client.get_paginator('list_access_keys')
    response = {}
    for response in paginator.paginate():
        True
    print(response)
    

if __name__ == "__main__":
    main()
    get_account_password_policy()
    check_access_key()