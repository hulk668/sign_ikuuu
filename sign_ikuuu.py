# -*- coding: utf-8 -*-
"""
ikuuu.top 多账号自动签到
=================================================================
相比旧版（Playwright 打开浏览器点验证码按钮）的改动：

  1. 去掉 Playwright，改成纯 requests 直接走登录协议，速度快得多，
     也不再要求运行环境能装浏览器。
  2. 自带极验 GeeTest v4 验证码处理。

关于验证码（重要）
-----------------------------------------------------------------
登录页 https://ikuuu.top/auth/login 用的是极验 GeeTest v4，
captchaId = cc96d05ba8b60f9112f76e18526fcb73，题型就是那个
"选 3 个符合右图的图片"的九宫格点选。

这套东西没法靠本地识别图片解决：提交给服务端的不是"点了哪几个格子"，
而是四个参数

    lot_number / captcha_output / pass_token / gen_time

其中 captcha_output 是官方 JS 用极验服务端下发的密钥把
"答案 + 轨迹 + 时间戳"加密后的密文，服务端还会把这四个值转发给
极验的 validate 接口做二次校验。就算图片识别得再准也生成不了合法密文，
所以现实做法只有三条（脚本都支持）：

  cookie 复用（默认优先，零成本，绝大多数情况下不用过验证码）
  打码平台 API（YesCaptcha / 2Captcha，约 0.01 元一次，全自动）
  手动模式（自己点一次，把参数贴进 captcha_solution.json）

环境变量
-----------------------------------------------------------------
ACCOUNTS            多账号，每行一个  邮箱:密码
CAPTCHA_PROVIDER    yescaptcha | 2captcha | manual | none   默认 none
CAPTCHA_KEY         打码平台 clientKey
CAPTCHA_PROXY       可选，打码平台需要走代理时填 http://user:pass@ip:port
TOTP_SECRET_<邮箱>  账号开了谷歌二步验证时填 base32 密钥
COOKIE_FILE         cookie 缓存路径，默认系统临时目录
COOKIE_JSON         可选，把 cookie 内容直接写进环境变量（容器环境用）
WX_CORPSECRET       PushPlus token

注意：仅用于自己账号的自动签到，不要用于批量注册 / 撞库。
"""

import json
import os
import tempfile
import time

import requests

# ─────────────────────────────
# 常量
# ─────────────────────────────

HOST = 'ikuuu.top'
BASE = 'https://' + HOST
LOGIN_URL = BASE + '/auth/login'
CHECKIN_URL = BASE + '/user/checkin'

# 极验 captchaId，从登录页里取到的，一般不常变
CAPTCHA_ID = 'cc96d05ba8b60f9112f76e18526fcb73'

USER_AGENT = (
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
    'AppleWebKit/537.36 (KHTML, like Gecko) '
    'Chrome/120.0.0.0 Safari/537.36'
)

BASE_HEADERS = {
    'User-Agent': USER_AGENT,
    'Accept-Language': 'zh-CN,zh;q=0.9,en;q=0.8'
}

POST_HEADERS = {
    'X-Requested-With': 'XMLHttpRequest',
    'Origin': BASE,
    'Referer': LOGIN_URL,
    'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8'
}

CORPSECRET = os.environ.get('WX_CORPSECRET') or ''

COOKIE_FILE = (
    os.environ.get('COOKIE_FILE')
    or os.path.join(tempfile.gettempdir(), 'ikuuu_cookies.json')
)

MANUAL_FILE = 'captcha_solution.json'

# 打码平台服务器在海外，部分业务要求走代理
PROXY = os.environ.get('CAPTCHA_PROXY') or None


# ─────────────────────────────
# PushPlus 推送
# ─────────────────────────────
def send_pushplus(title, content):
    """
    通过 PushPlus 推送消息到微信
    文档：https://www.pushplus.plus/doc/guide/api.html
    """

    if not CORPSECRET:
        print('未配置 WX_CORPSECRET，跳过推送')
        return

    try:
        resp = requests.post(
            'https://www.pushplus.plus/send',
            json={
                'token': CORPSECRET,
                'title': title,
                'content': content,
                'template': 'txt'
            },
            timeout=15
        )
        print(f'PushPlus 推送结果：{resp.json()}')

    except Exception as e:
        print(f'PushPlus 推送失败：{str(e)}')


# ─────────────────────────────
# 邮箱脱敏
# ─────────────────────────────
def mask_email(email):
    """
    abc123@gmail.com
    -> a****3@gmail.com
    """

    if '@' not in email:
        return email

    name, domain = email.split('@', 1)

    if len(name) <= 1:
        masked = name

    elif len(name) == 2:
        masked = name[0] + '*'

    else:
        masked = name[0] + '*' * (len(name) - 2) + name[-1]

    return f'{masked}@{domain}'


# ─────────────────────────────
# Session
# ─────────────────────────────
def new_session():
    """
    新建一个带 UA 的会话
    """

    session = requests.session()
    session.headers.update(BASE_HEADERS)

    return session


# ─────────────────────────────
# Cookie 存取
# ─────────────────────────────
def _read_store():
    """
    cookie 仓库：优先读环境变量 COOKIE_JSON（容器冷启动也能用），
    其次读缓存文件
    """

    raw = os.environ.get('COOKIE_JSON')

    if raw:
        try:
            return json.loads(raw)
        except Exception:
            print('[cookie] COOKIE_JSON 解析失败，改用缓存文件')

    if os.path.exists(COOKIE_FILE):
        try:
            with open(COOKIE_FILE, encoding='utf-8') as f:
                return json.load(f)
        except Exception:
            print('[cookie] 缓存文件解析失败，忽略')

    return {}


def save_cookies(email, session):
    """
    按账号持久化 cookie，下次直接复用，省掉验证码
    """

    store = _read_store()

    store[email] = {
        'ts': int(time.time()),
        'cookies': [
            {
                'name': c.name,
                'value': c.value,
                'domain': c.domain,
                'path': c.path
            }
            for c in session.cookies
        ]
    }

    try:
        with open(COOKIE_FILE, 'w', encoding='utf-8') as f:
            json.dump(store, f, ensure_ascii=False, indent=2)
        print(f'[cookie] 已保存到 {COOKIE_FILE}')
    except Exception as e:
        print(f'[cookie] 写入失败：{str(e)}（容器环境建议改用 COOKIE_JSON）')


def load_cookies(email, session):
    """
    把缓存的 cookie 灌进 session，返回是否命中
    """

    item = _read_store().get(email)

    if not item:
        return False

    for c in item.get('cookies', []):
        session.cookies.set(
            c['name'],
            c['value'],
            domain=c.get('domain'),
            path=c.get('path', '/')
        )

    days = (time.time() - item.get('ts', 0)) / 86400
    print(f'[cookie] 命中缓存，已存放 {days:.1f} 天')

    return True


# ─────────────────────────────
# 打码平台：GeeTest v4
# ─────────────────────────────
def _poll_task(provider, key, task_id):
    """
    轮询打码平台结果，返回 solution dict
    """

    if provider == 'yescaptcha':
        url = 'https://api.yescaptcha.com/getTaskResult'
    else:
        url = 'https://api.2captcha.com/getTaskResult'

    for idx in range(60):
        time.sleep(3)

        resp = requests.post(
            url,
            json={'clientKey': key, 'taskId': task_id},
            timeout=20
        )

        result = resp.json()

        if result.get('errorId') not in (0, None):
            raise Exception(f'打码平台出错：{result}')

        status = result.get('status')

        if status == 'ready':
            return result['solution']

        if status == 'processing':
            print(f'[打码] 识别中... ({idx + 1})')
            continue

        raise Exception(f'打码平台异常返回：{result}')

    raise Exception('打码超时')


def _split_proxy(proxy):
    """
    http://user:pass@ip:port -> (host, port, user, pwd)
    """

    body = proxy.split('://', 1)[-1]

    if '@' in body:
        auth, addr = body.split('@')
    else:
        auth, addr = None, body

    host, port = addr.split(':')

    if auth:
        user, pwd = auth.split(':', 1)
    else:
        user, pwd = '', ''

    return host, int(port), user, pwd


def solve_geetest_v4(provider, key):
    """
    向打码平台申请一个 GeeTest v4 的通过凭证
    返回 {lot_number, captcha_output, pass_token, gen_time}
    """

    if provider == 'yescaptcha':
        create_url = 'https://api.yescaptcha.com/createTask'
        task = {
            'type': 'GeeTestTask',
            'websiteUrl': LOGIN_URL,
            'gt': CAPTCHA_ID,
            'version': 4,
            'initParameters': {'riskType': 'slide'}
        }

    elif provider == '2captcha':
        create_url = 'https://api.2captcha.com/createTask'
        task = {
            'type': 'GeeTestTaskProxyless',
            'websiteURL': LOGIN_URL,
            'gt': CAPTCHA_ID,
            'version': 4,
            'initParameters': {'riskType': 'slide'}
        }

    else:
        raise Exception(f'不支持的打码平台：{provider}')

    if PROXY:
        host, port, user, pwd = _split_proxy(PROXY)
        task['type'] = 'GeeTestTask'
        task.update({
            'proxyType': 'http',
            'proxyAddress': host,
            'proxyPort': port,
            'proxyLogin': user,
            'proxyPassword': pwd
        })

    resp = requests.post(
        create_url,
        json={'clientKey': key, 'task': task},
        timeout=25
    )

    result = resp.json()
    print(f'[打码] createTask -> {result}')

    if result.get('errorId') not in (0, None) or not result.get('taskId'):
        raise Exception(f'打码任务创建失败：{result}')

    solution = _poll_task(provider, key, result['taskId'])
    print(f'[打码] 完成 lot_number={solution.get("lot_number")}')

    need = ('lot_number', 'captcha_output', 'pass_token', 'gen_time')
    missing = [k for k in need if not solution.get(k)]

    if missing:
        raise Exception(f'打码平台返回缺少字段 {missing}：{solution}')

    return solution


def solve_geetest_manual():
    """
    手动模式：自己过完验证后把参数写进 captcha_solution.json
    """

    if not os.path.exists(MANUAL_FILE):
        raise Exception(
            f'手动模式需要当前目录下的 {MANUAL_FILE}，内容形如：\n'
            '{"lot_number":"...","captcha_output":"...",'
            '"pass_token":"...","gen_time":"..."}\n'
            '获取方式：登录页按 F12，手动过一次验证码后，'
            '在 Console 里执行下面任一行\n'
            'JSON.stringify(geetestV4Handler.getValidate())\n'
            'JSON.stringify(window.Captcha.getResponse())'
        )

    with open(MANUAL_FILE, encoding='utf-8') as f:
        solution = json.load(f)

    # 凭证是一次性的，用过即删
    os.remove(MANUAL_FILE)

    return solution


def get_solution(provider, key):
    """
    获取极验凭证
    """

    if provider == 'manual':
        return solve_geetest_manual()

    return solve_geetest_v4(provider, key)


# ─────────────────────────────
# 登录
# ─────────────────────────────
def build_login_data(email, passwd, solution, page_loaded_at):
    """
    对应页面里 buildLoginRequest('password') 的字段：

        host / phase / email / passwd / remember_me / pageLoadedAt
        captcha_result[lot_number|captcha_output|pass_token|gen_time]

    jQuery 序列化嵌套对象就是这个 [] 形式，服务端按同样结构取值
    """

    return {
        'host': HOST,
        'phase': 'password',
        'email': email,
        'passwd': passwd,
        'remember_me': 'on',
        'pageLoadedAt': str(page_loaded_at),
        'captcha_result[lot_number]': solution['lot_number'],
        'captcha_result[captcha_output]': solution['captcha_output'],
        'captcha_result[pass_token]': solution['pass_token'],
        'captcha_result[gen_time]': solution['gen_time']
    }


def post_login(session, data):
    """
    提交登录请求并解析 JSON
    """

    resp = session.post(
        LOGIN_URL,
        data=data,
        headers=POST_HEADERS,
        timeout=25
    )

    try:
        return resp.json()

    except Exception:
        raise Exception(
            f'登录接口返回非 JSON（{resp.status_code}）：{resp.text[:300]}'
        )


def do_login(email, passwd, provider, key, totp_secret=None):
    """
    走一次完整登录，成功返回带 cookie 的 session
    """

    safe_email = mask_email(email)

    print(f'\n开始登录流程：{safe_email}')

    session = new_session()

    # 建立会话，拿到初始 cookie
    print('[1/3] 打开登录页...')
    session.get(LOGIN_URL, timeout=25)

    page_loaded_at = int(time.time() * 1000)

    print(f'[2/3] 获取极验凭证（provider={provider}）...')
    solution = get_solution(provider, key)

    print('[3/3] 提交登录...')
    result = post_login(
        session,
        build_login_data(email, passwd, solution, page_loaded_at)
    )

    phase = result.get('phase')
    print(f'-> phase={phase} result={result.get("result")} msg={result.get("msg")}')

    # 账号开了谷歌二步验证
    if phase == 'totp':

        if not totp_secret:
            raise Exception(
                '账号开启了二步验证，需配置环境变量 TOTP_SECRET_<邮箱>'
            )

        import pyotp

        code = pyotp.TOTP(totp_secret).now()

        result = post_login(session, {
            'host': HOST,
            'phase': 'totp',
            'code': code
        })

        phase = result.get('phase')
        print(f'-> 二步验证后 phase={phase} msg={result.get("msg")}')

    if phase == 'email_code':
        raise Exception('该账号需要邮箱验证码登录，脚本无法自动完成')

    if phase == 'reverse_email_verify':
        raise Exception('该账号需要用邮箱发信验证登录，脚本无法自动完成')

    if phase != 'authenticated':
        raise Exception(result.get('msg') or f'登录失败：{result}')

    print('登录成功')

    return session


# ─────────────────────────────
# 签到
# ─────────────────────────────
def post_checkin(session):
    """
    执行签到，cookie 失效时会抛 PermissionError
    """

    resp = session.post(
        CHECKIN_URL,
        headers=POST_HEADERS,
        timeout=20
    )

    try:
        result = resp.json()

    except Exception:
        raise Exception(
            f'签到返回非 JSON（{resp.status_code}）：{resp.text[:200]}'
        )

    msg = result.get('msg', '未知结果')

    # cookie 失效时服务端会提示先登录
    for keyword in ('登录', 'login', 'Login'):
        if keyword in msg:
            raise PermissionError(msg)

    return msg


# ─────────────────────────────
# 单账号处理
# ─────────────────────────────
def checkin_one_account(email, passwd, provider, key):

    safe_email = mask_email(email)

    totp_secret = os.environ.get(f'TOTP_SECRET_{email}') or None

    try:

        # ① 优先复用 cookie，绝大多数情况下不需要过验证码
        if provider != 'manual':

            session = new_session()

            if load_cookies(email, session):

                try:

                    msg = post_checkin(session)

                    print(f'cookie 有效，签到完成：{msg}')

                    return f'✅ {safe_email} -> {msg}'

                except PermissionError as e:

                    print(f'cookie 已失效（{e}），改走登录流程')

        if provider == 'none':
            return f'❌ {safe_email} -> cookie 已失效且未配置 CAPTCHA_PROVIDER'

        # ② 完整登录
        session = do_login(email, passwd, provider, key, totp_secret)

        save_cookies(email, session)

        msg = post_checkin(session)

        return f'✅ {safe_email} -> {msg}'

    except Exception as e:

        print(f'❌ {safe_email} -> {str(e)}')

        return f'❌ {safe_email} -> {str(e)}'


# ─────────────────────────────
# 读取账号配置
# ─────────────────────────────
def parse_accounts():
    """
    环境变量 ACCOUNTS 格式：

        aaa@qq.com:123456
        bbb@qq.com:abcdef
    """

    accounts_str = os.environ.get('ACCOUNTS')

    if not accounts_str:
        raise Exception('未配置 ACCOUNTS 环境变量')

    accounts = []

    for line in accounts_str.strip().splitlines():

        line = line.strip()

        if line and ':' in line:

            email, passwd = line.split(':', 1)

            accounts.append((email.strip(), passwd.strip()))

    if not accounts:
        raise Exception('未读取到账号')

    return accounts


# ─────────────────────────────
# 主函数
# ─────────────────────────────
def handler(event=None, context=None):

    try:

        accounts = parse_accounts()

        provider = (os.environ.get('CAPTCHA_PROVIDER') or 'none').lower()
        key = os.environ.get('CAPTCHA_KEY') or ''

        print(f'\n共发现 {len(accounts)} 个账号，登录方式：{provider}')

        all_result = []

        # 逐个账号签到
        for idx, (email, passwd) in enumerate(accounts, 1):

            print('\n' + '=' * 50)
            print(f'开始处理第 {idx} 个账号')
            print('=' * 50)

            result = checkin_one_account(email, passwd, provider, key)

            all_result.append(result)

        # 汇总结果
        final_msg = '\n'.join(all_result)

        print('\n最终结果：')
        print(final_msg)

        # PushPlus 推送通知
        send_pushplus('[ikuuu] 多账号签到结果', final_msg)

    except Exception as e:

        content = f'签到失败：{str(e)}'

        print(content)

        send_pushplus('[ikuuu] 签到结果', content)

    return '任务完成'


if __name__ == "__main__":
    handler()
