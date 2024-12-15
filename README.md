# Job Board API

채용 공고 관리를 위한 RESTful API 서버입니다.

## 기술 스택

- Python 3.8+
- Flask
- MySQL
- Swagger UI

## 설치 방법

1. 가상환경 생성 및 활성화:
bash
python3 -m venv virtualenv
source virtualenv/bin/activate

2. 의존성 설치:
bash
pip install -r requirements.txt

## 실행 방법

### 개발 서버 실행

bash
python3 -m venv virtualenv
source virtualenv/bin/activate



### 프로덕션 서버 실행
1. 기존 실행 중인 서버 확인 및 종료:
bash
ps aux | grep python
kill -9 [프로세스ID]


2. gunicorn으로 서버 실행:
bash
gunicorn -b 0.0.0.0:19051 app:app

## API 문서

API 문서는 Swagger UI를 통해 확인할 수 있습니다:
- http://http://113.198.66.75:19051/api/docs

## 데이터베이스 설정

MySQL 데이터베이스 연결 정보:
- Host: 113.198.66.75
- Port: 13145
- Database: wsd3

## CSV 데이터 로드

데이터베이스에 CSV 파일을 로드하려면:
bash
python3 csv2db.py

## API 엔드포인트

- `/auth/register`: 사용자 등록
- `/auth/login`: 로그인
- `/auth/profile`: 프로필 관리
- `/jobs`: 채용공고 관리
- `/applications`: 지원서 관리
- `/bookmarks`: 북마크 관리

## 라이센스

This project is licensed under the MIT License

This project is licensed under the MIT License