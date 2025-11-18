from flask import Flask, render_template, request, redirect, url_for, session, jsonify
import jwt
import requests
import json
from datetime import datetime, timedelta
import logging

# 配置日志
logging.basicConfig(level=logging.DEBUG)
logger = logging.getLogger(__name__)

app = Flask(__name__)
app.secret_key = 'wxaVCzToGqS3G1w6GydIUe4YzkgrmfKz'  # 请在生产环境中更改

# JWT配置
JWT_SECRET = 'wxaVCzToGqS3G1w6GydIUe4YzkgrmfKz'  # 需要与SSO服务端的密钥一致
JWT_ALGORITHM = 'HS256'

# SSO配置
SSO_LOGIN_URL = "https://sso.example.com/jwt/sso?targetUrl=http%3A%2F%2Flwww.example.com%3A5000%2Fjwt%2Fcallback"  # 替换为实际的SSO登录URL
SSO_CALLBACK_URL = "http://www.example.com:5000/jwt/callback"
USER_INFO_URL = "https://sso.example.com/jwt/check"  # 替换为实际的用户信息接口URL


@app.route('/')
def index():
    """首页 - 显示登录按钮"""
    return render_template('index.html')


@app.route('/sso-login')
def sso_login():
    """跳转到SSO登录页面"""
    return redirect(SSO_LOGIN_URL)


@app.route('/jwt/callback')
def jwt_callback():
    """JWT回调接口 - 处理SSO返回的token"""
    try:
        token = request.args.get('jwt')
        if not token:
            return jsonify({'code': 50000, 'msg': 'Token is required'}), 400

        logger.info(f"Received token: {token}")

        # 验证JWT token
        try:
            decoded_token = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            logger.info(f"Decoded token: {decoded_token}")
        except jwt.ExpiredSignatureError:
            return jsonify({'code': 50000, 'msg': 'Token has expired'}), 401
        except jwt.InvalidTokenError as e:
            logger.error(f"Invalid token: {str(e)}")
            return jsonify({'code': 50000, 'msg': 'Invalid token'}), 401

        # 保存token到session
        session['jwt_token'] = token
        # session['token_decoded'] = decoded_token

        # 获取用户信息
        user_info = get_user_info(token)
        if user_info:
            session['user_info'] = user_info
            return redirect(url_for('dashboard'))
        else:
            return jsonify({'code': 50000, 'msg': 'Failed to get user info'}), 500

    except Exception as e:
        logger.error(f"Callback error: {str(e)}")
        return jsonify({'code': 50000, 'msg': f'Internal server error: {str(e)}'}), 500


def get_user_info(token):
    """调用用户信息接口"""
    try:
        headers = {
            'Authorization': f'Bearer {token}',
            'Content-Type': 'application/json'
        }

        logger.info(f"Requesting user info with token: {token}")

        # 模拟用户信息接口调用
        # 在实际环境中，这里应该是真实的API调用
        response = requests.get(USER_INFO_URL, headers=headers, timeout=10, verify=False)

        logger.info(f"User info response status: {response.status_code}")
        logger.info(f"User info response body: {response.text}")

        if response.status_code == 200:
            data = response.json()
            if data.get('code') == 10000:  # 假设10000表示成功
                return data.get('data', {})
            else:
                logger.error(f"API returned error: {data.get('msg')}")
                return None
        else:
            logger.error(f"API request failed with status: {response.status_code}")
            return None

    except requests.exceptions.RequestException as e:
        logger.error(f"Request error: {str(e)}")
        return None
    except Exception as e:
        logger.error(f"Unexpected error: {str(e)}")
        return None

@app.route('/dashboard')
def dashboard():
    """用户仪表板"""
    if 'user_info' not in session:
        return redirect(url_for('index'))

    user_info = session.get('user_info', {})
    return render_template('dashboard.html', user_info=user_info)


@app.route('/logout')
def logout():
    """退出登录"""
    session.clear()
    return redirect(url_for('index'))


@app.route('/api/user-info')
def api_user_info():
    """模拟用户信息接口（用于测试）"""
    token = request.headers.get('Authorization', '').replace('Bearer ', '')

    if not token:
        return jsonify({'code': 50000, 'msg': 'Token is required'}), 401

    try:
        # 验证token
        decoded = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])

        # 模拟返回用户信息
        user_data = {
            "userid": "zhangsan",
            "userNo": "zhangsan",
            "email": "zhangsan@example.com",
            "name": "张三",
            "department": "技术部"
        }

        return jsonify({
            "code": 10000,
            "msg": "成功",
            "data": user_data
        })

    except jwt.ExpiredSignatureError:
        return jsonify({'code': 50000, 'msg': 'Token has expired'}), 401
    except jwt.InvalidTokenError:
        return jsonify({'code': 50000, 'msg': 'Invalid token'}), 401


@app.route('/api/generate-test-token')
def generate_test_token():
    """生成测试用的JWT token（仅用于测试）"""
    payload = {
        'userid': 'zhangsan',
        'exp': datetime.utcnow() + timedelta(hours=1),
        'iat': datetime.utcnow()
    }

    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)
    return jsonify({'token': token})


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5000, debug=True)