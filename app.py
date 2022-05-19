from datetime import datetime, timedelta
from functools import wraps
import hashlib
import json
import re
from bson import ObjectId
from flask import Flask, abort, jsonify, request, Response
from flask_cors import CORS  # flask 연결
from pymongo import MongoClient  # DB
import jwt

SECRET_KEY = 'tutle'

app = Flask(__name__)
cors = CORS(app, resources={r"*": {"origins": "*"}})
client = MongoClient('localhost', 27017)
db = client.turtle


########################################################################
########################################################################
########################################################################
# 토근 활성화
########################################################################
########################################################################
########################################################################
def authorize(f):
    @wraps(f)
    def decorated_function():
        if not 'Authorization' in request.headers:  # headers 에서 Authorization 인증을 하고
            abort(401)  # Authorization 으로 토큰이 오지 않았다면 에러 401
        # Authorization 이 headers에 있다면 token 값을 꺼내온다.
        token = request.headers['Authorization']
        try:
            user = jwt.decode(token, SECRET_KEY, algorithms=[
                              'HS256'])  # 꺼내온 token 값을 디코딩해서 꺼내주고
        except:
            abort(401)  # 디코딩이 안될 경우 에러 401
        return f(user)
    return decorated_function


@app.route('/')
@authorize  # decorated 함수 적용
def hello_world(user):
    print(user)  # 토큰 값 출력
    return jsonify({'message': 'success'})


########################################################################
########################################################################
########################################################################
# 회원가입
########################################################################
########################################################################
########################################################################
@app.route("/signup", methods=["POST"])
def sign_up():

    data = json.loads(request.data)  # fetch() 사용 시 필수 구문

    # 이메일, 비밀번호
    email_receive = data["email"]
    password_receive = data["password"]

    # 이메일/패스워드가 없을 때 에러 처리
    if not email_receive or not password_receive:
        return jsonify({'msg': '이메일 혹은 패스워드를 입력해주세요!'})

    if '@' not in email_receive:
        return jsonify({'msg': '이메일 형식이 아닙니다.'})

    # 이메일 중복 처리
    print(email_receive)
    # print(db.users.find_one({'email': email_receive}))
    if db.turtle.find_one({'email': email_receive}):
        return jsonify({'msg': '중복된 이메일입니다.'})

    password_hash = hashlib.sha256(
        data['password'].encode('utf-8')).hexdigest()

    doc = {
        'email': data.get('email'),
        'password': password_hash
    }

    db.turtle.insert_one(doc)

    return jsonify({'msg': 'success'})


########################################################################
########################################################################
########################################################################
# 로그인
########################################################################
########################################################################
########################################################################
@app.route('/login', methods=['POST'])
def login():
    data = json.loads(request.data)
    print(data)

    email = data.get("email")
    password = data.get("password")
    hashed_pw = hashlib.sha256(password.encode('utf-8')).hexdigest()  # 복호화
    print(hashed_pw)

    result = db.turtle.find_one({
        "email": email,
        "password": hashed_pw
    })
    print(result)

    if result is None:
        return jsonify({'message': '이메일이나 비밀번호가 맞지 않습니다.'}), 401

    payload = {
        'id': str(result['_id']),
        'exp': datetime.utcnow() + timedelta(seconds=60 * 60 * 24)
    }
    token = jwt.encode(payload, SECRET_KEY, algorithm='HS256')
    print(token)

    return jsonify({'message': 'success', "token": token})


########################################################################
########################################################################
########################################################################
# 유저정보 불러오기
########################################################################
########################################################################
########################################################################
@app.route('/getuserinfo', methods=['GET'])
@authorize
def get_user_info(user):
    result = db.turtle.find_one({
        '_id': ObjectId(user["id"])

    })

    print(result)

    return jsonify({'message': 'success', 'email': result['email']})


########################################################################
########################################################################
########################################################################
# 게시글 포스팅
########################################################################
########################################################################
########################################################################
@app.route('/article', methods=['POST'])  # 계정의 소유자만 포스트 할 수 있는 영역
@authorize
def post_article(user):
    data = json.loads(request.data)
    print(data)

    # user 의 id 값을 가져와서 ObjectId 시켜준 후 DB 에서 가져온다.
    # 실제 email 정보를 저장하기 위함
    db_user = db.turtle.find_one({'_id': ObjectId(user.get('id'))})

    now = datetime.now().strftime("%H:%M:%S")

    doc = {
        'title': data.get('title', None),
        'content': data.get('content', None),
        'user': user['id'],  # user '_id' 를 저장
        'user_eamil': db_user['email'],  # db_user 에서 가져온 user 의 email 저장
        'time': now
    }

    print(doc)

    db.article.insert_one(doc)

    return jsonify({'message': 'success'})


########################################################################
########################################################################
########################################################################
# 게시글 리스팅
########################################################################
########################################################################
########################################################################
@app.route('/article', methods=['GET'])
def get_article():
    articles = list(db.article.find())  # 모든 article 데이터를 불러온다
    # 반복문을 돌리고
    for article in articles:
        # articles 의 데이터 중에 .get 으로 가져와서 "title" 를 가져온다.
        print(article.get("title"))
        # article 의 _id 를 str _id 로 변환
        article["_id"] = str(article["_id"])

    # response 으로 보내줄 articles 를 정의한다.
    return jsonify({'message': 'success', 'articles': articles})


########################################################################
########################################################################
########################################################################
# 변수명
########################################################################
########################################################################
########################################################################
@app.route('/article/<article_id>', methods=['GET'])
def get_article_detail(article_id):
    print(article_id)
    article = db.article.find_one({"_id": ObjectId(article_id)})
    print(article)
    article["_id"] = str(article["_id"])

    return jsonify({'message': 'success', "article": article})


if __name__ == '__main__':
    app.run('0.0.0.0', port=5002, debug=True)
