# AWS-ISMS-CheckTool
AWS 클라우드에서 ISMS 인증 기준을 자동으로 체크
aws-cli + boto3 사용

사전 설치  
aws-cli  

aws configure 로 access key 인증  

현재 구현된 항목 

IAM USER 최근 콘솔 로그인 체크  
[30일 이내=양호, 30일 초과=확인]  

IAM USER 액세스 키 수명  
[60일 이내=양호, 60일 초과=삭제]  

IAM USER 액세스 키 최근 사용 체크  
[30일 이내 사용(양호), 30일 초과=확인]  
// 2022-09-19    

IAM 역할 최근 사용일자 체크  
[30일 이내 사용(양호), 30일 초과=확인]  
// 2022-09-20      

사용 중인 모든 리전과 EC2의 Security Group List 액셀 파일로 출력 기능 추가
[설명 없는 Default Out bound Rule 은 제외]
// 2022-10-07
