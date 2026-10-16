from playwright.sync_api import sync_playwright
import requests
import os
import time
import json

# PushPlus 配置
corpsecret = os.environ.get('WX_CORPSECRET') or ''

USER_AGENT = (
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
    'AppleWebKit/537.36 (KHTML, like Gecko) '
    'Chrome/120.0.0.0 Safari/537.36'
)


# ─────────────────────────────
# PushPlus 推送
# ─────────────────────────────
def send_pushplus(title, content):
    """
    通过 PushPlus 推送消息到微信
    文档：https://www.pushplus.plus/doc/guide/api.html
    """
    if not corpsecret:
        print('未配置 WX_CORPSECRET，跳过推送')
        return

    url = 'https://www.pushplus.plus/send'

    data = {
        'token': corpsecret,
        'title': title,
        'content': content,
        'template': 'txt'
    }

    try:
        resp = requests.post(
            url,
            json=data,
            timeout=15
        )
        result = resp.json()
        print(f'PushPlus 推送结果：{result}')
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
        masked = (
            name[0]
            + '*' * (len(name) - 2)
            + name[-1]
        )

    return f'{masked}@{domain}'


# ─────────────────────────────
# Geetest 图形验证码处理（新增）
# ─────────────────────────────
# 说明：
#   ikuuu.top 登录页使用 Geetest V4：
#     captchaId   = cc96d05ba8b60f9112f76e18526fcb73
#     captcha_mode= adaptive（自适应：先做无感判断，失败才出题）
#     captcha_type= nine（九宫格点选，默认选 3 张）
#   因此真实浏览器点击「点我开始验证」后，多数情况会直接通过、无需识别；
#   只有被判定为高风险（无头浏览器 / 机房 IP 等）时，才会弹出你截图里的
#   九宫格点选验证。
#
#   站点登录逻辑（抓包确认）：
#     POST /auth/login 前会执行
#       if (!Captcha.isReady()) { 提示"请先完成验证码验证" }
#       requestData.captcha_result = Captcha.getResponse()
#   因此只要把识别结果塞进 window.Captcha，点击登录即可通过。
#
#   处理优先级（任一步不可用都不会中断原有流程）：
#     1) 原生点击直接通过（免费，最常见）
#     2) 配置了 CAPTCHA_KEY -> 调用打码平台自动识别
#     3) 未配置 CAPTCHA_KEY -> PLAYWRIGHT_HEADLESS=0 时等待人工完成
#
#   相关环境变量（可不配置，不配置即保持原行为）：
#     CAPTCHA_KEY          打码平台密钥
#     CAPTCHA_PROVIDER     yescaptcha（默认） / 2captcha
#     CAPTCHA_API_BASE     自定义接口地址（可选，兼容自建代理）
#     CAPTCHA_TIMEOUT      打码轮询超时秒数，默认 120
#     CAPTCHA_MANUAL_WAIT  人工过验证等待秒数，默认 180
#     PLAYWRIGHT_HEADLESS  1=无头（默认） 0=有头

CAPTCHA_KEY = os.environ.get('CAPTCHA_KEY') or ''
CAPTCHA_PROVIDER = (os.environ.get('CAPTCHA_PROVIDER') or 'yescaptcha').strip().lower()
CAPTCHA_API_BASE = (os.environ.get('CAPTCHA_API_BASE') or '').strip()
CAPTCHA_TIMEOUT = int(os.environ.get('CAPTCHA_TIMEOUT') or '120')
CAPTCHA_MANUAL_WAIT = int(os.environ.get('CAPTCHA_MANUAL_WAIT') or '180')
PLAYWRIGHT_HEADLESS = (os.environ.get('PLAYWRIGHT_HEADLESS') or '1') != '0'


# 在页面脚本执行前注入：劫持 initGeetest4 / initGeetest，记录 captchaId 等参数
GEETEST_HOOK_JS = r"""
(function () {
    function capture(cfg) {
        try {
            cfg = cfg || {};
            if (cfg.captchaId) window.__gt4_captcha_id = cfg.captchaId;
            if (cfg.captcha_id) window.__gt4_captcha_id = cfg.captcha_id;
            if (cfg.gt) window.__gt3_gt = cfg.gt;
            if (cfg.challenge) window.__gt3_challenge = cfg.challenge;
        } catch (e) {}
    }
    function wrap(name) {
        var stored;
        try {
            Object.defineProperty(window, name, {
                configurable: true,
                get: function () { return stored; },
                set: function (fn) {
                    if (typeof fn !== 'function') { stored = fn; return; }
                    stored = function (cfg, cb) {
                        capture(cfg);
                        var wrapped = cb;
                        if (typeof cb === 'function') {
                            wrapped = function (instance) {
                                try { window.__gt_handler = instance; } catch (e) {}
                                return cb(instance);
                            };
                        }
                        return fn.call(this, cfg, wrapped);
                    };
                }
            });
        } catch (e) {}
    }
    wrap('initGeetest4');
    wrap('initGeetest');
})();
"""


def _geetest_state(page):
    """读取页面当前验证码状态；任何异常都返回空字典，保证不影响主流程。"""
    try:
        return page.evaluate(
            """
            () => {
                const pickVisible = (sels) => {
                    for (const s of sels) {
                        const el = document.querySelector(s);
                        if (!el) continue;
                        const r = el.getBoundingClientRect();
                        const st = getComputedStyle(el);
                        if (r.width > 0 && r.height > 0 &&
                            st.display !== 'none' &&
                            st.visibility !== 'hidden') return true;
                    }
                    return false;
                };
                let ready = false;
                try {
                    ready = !!(window.Captcha && window.Captcha.isReady && window.Captcha.isReady());
                } catch (e) { ready = false; }
                let captchaId = window.__gt4_captcha_id || null;
                if (!captchaId) {
                    try {
                        const html = document.documentElement.innerHTML;
                        const m = html.match(/captchaId\\s*[:=]\\s*['"]([0-9a-f]{32})['"]/i)
                               || html.match(/captcha_id=([0-9a-f]{32})/i);
                        if (m) captchaId = m[1];
                    } catch (e) {}
                }
                let successVisible = pickVisible(['.geetest_success']);
                const popupSels = [
                    '.geetest_box_wrap', '.geetest_popup_wrap', '.geetest_nine',
                    '.geetest_window', '.geetest_wind', '.geetest_box',
                    '.geetest_panel_box', '.geetest_popup'
                ];
                let popupVisible = pickVisible(popupSels);
                if (!popupVisible) {
                    // 兜底：任何尺寸较大且定位为浮层的 geetest 元素，视为弹出了验证码
                    popupVisible = Array.from(
                        document.querySelectorAll('[class*="geetest"]')
                    ).some((el) => {
                        const r = el.getBoundingClientRect();
                        if (r.width < 200 || r.height < 140) return false;
                        const st = getComputedStyle(el);
                        if (st.display === 'none' || st.visibility === 'hidden') return false;
                        return st.position === 'fixed' || st.position === 'absolute';
                    });
                }
                return {
                    isReady: ready,
                    captchaId: captchaId,
                    gt: window.__gt3_gt || null,
                    popupVisible: popupVisible,
                    successVisible: successVisible
                };
            }
            """
        ) or {}
    except Exception:
        return {}


def _solve_yescaptcha_v4(captcha_id, page_url):
    """YesCaptcha（JSON 接口）识别 Geetest V4。"""
    base = CAPTCHA_API_BASE or 'https://api.yescaptcha.com'

    payload = {
        'clientKey': CAPTCHA_KEY,
        'task': {
            'type': 'GeetestTaskProxyLess',
            'websiteURL': page_url,
            'gt': captcha_id,
            'version': 4,
            'initParameters': {'captcha_id': captcha_id}
        }
    }

    resp = requests.post(
        base + '/createTask',
        json=payload,
        timeout=20
    ).json()

    if resp.get('errorId'):
        raise Exception(f'打码任务创建失败：{resp.get("errorDescription") or resp}')

    task_id = resp.get('taskId')

    print(f'打码任务已创建：{task_id}，等待识别结果...')

    deadline = time.time() + CAPTCHA_TIMEOUT

    while time.time() < deadline:

        time.sleep(3)

        r = requests.post(
            base + '/getTaskResult',
            json={'clientKey': CAPTCHA_KEY, 'taskId': task_id},
            timeout=20
        ).json()

        if r.get('errorId'):
            raise Exception(f'打码查询失败：{r.get("errorDescription") or r}')

        if r.get('status') == 'ready':

            sol = r.get('solution') or {}

            return {
                'lot_number': sol.get('lot_number'),
                'captcha_output': sol.get('captcha_output'),
                'pass_token': sol.get('pass_token'),
                'gen_time': sol.get('gen_time')
            }

    raise Exception('打码识别超时')


def _solve_2captcha_v4(captcha_id, page_url):
    """2Captcha（经典接口）识别 Geetest V4。"""
    base = CAPTCHA_API_BASE or 'https://2captcha.com'

    create = requests.post(
        base + '/in.php',
        data={
            'key': CAPTCHA_KEY,
            'method': 'geetest',
            'captcha_id': captcha_id,
            'pageurl': page_url,
            'json': 1
        },
        timeout=20
    ).json()

    if create.get('status') != 1:
        raise Exception(f'打码任务创建失败：{create.get("request") or create}')

    task_id = create.get('request')

    print(f'打码任务已创建：{task_id}，等待识别结果...')

    deadline = time.time() + CAPTCHA_TIMEOUT

    while time.time() < deadline:

        time.sleep(4)

        r = requests.get(
            base + '/res.php',
            params={
                'key': CAPTCHA_KEY,
                'action': 'get',
                'id': task_id,
                'json': 1
            },
            timeout=20
        ).json()

        if r.get('status') != 1:
            if r.get('request') == 'CAPCHA_NOT_READY':
                continue
            raise Exception(f'打码查询失败：{r.get("request") or r}')

        # 返回格式：captcha_id|lot_number|pass_token|gen_time|captcha_output
        parts = (r.get('request') or '').split('|')

        if len(parts) < 5:
            raise Exception(f'打码结果格式异常：{r.get("request")}')

        return {
            'lot_number': parts[1],
            'pass_token': parts[2],
            'gen_time': parts[3],
            'captcha_output': parts[4]
        }

    raise Exception('打码识别超时')


def solve_geetest_v4(captcha_id, page_url):
    """按配置选择打码平台。"""
    if not captcha_id:
        raise Exception('未获取到 captchaId，无法提交打码')

    if CAPTCHA_PROVIDER == '2captcha':
        return _solve_2captcha_v4(captcha_id, page_url)

    return _solve_yescaptcha_v4(captcha_id, page_url)


def _inject_geetest_result(page, result):
    """把打码结果注入页面，让站点自身的登录请求直接读到"已通过"状态。"""
    page.evaluate(
        """
        (res) => {
            window.Captcha = window.Captcha || {};
            window.Captcha.isReady = function () { return true; };
            window.Captcha.getResponse = function () { return res; };
            window.Captcha.getProvider = function () { return 'geetest_v4'; };
            try {
                const close = document.querySelector('.geetest_close');
                if (close) close.click();
            } catch (e) {}
        }
        """,
        result
    )


def _dismiss_geetest_popup(page):
    """隐藏验证码浮层，避免遮挡后续「登录」按钮的点击。"""
    try:
        page.evaluate(
            """
            () => {
                document.querySelectorAll(
                    '.geetest_box_wrap, .geetest_popup_wrap, .geetest_window, .geetest_mask, .geetest_mask_layer, .geetest_box'
                ).forEach(function (el) {
                    try { el.style.display = 'none'; } catch (e) {}
                });
            }
            """
        )
    except Exception:
        pass


def _geetest_passed(state):
    """判断验证码是否已通过：站点 isReady 为主信号，.geetest_success 为兜底信号。"""
    state = state or {}
    return bool(state.get('isReady') or state.get('successVisible'))


def _click_geetest_button(page):
    """
    定位并点击「点我开始验证」按钮。
    返回实际点击到的选择器；未找到返回 None。
    使用真实鼠标事件，兼容极验对 mousedown/mouseup 的事件绑定。
    """
    # 等待组件渲染出按钮（最多 10 秒，超时也不阻塞原有流程）
    try:
        page.wait_for_selector(
            '.geetest_btn_click, .geetest_btn, .embed-captcha button',
            timeout=10000,
            state='attached'
        )
    except Exception:
        pass

    try:
        box = page.evaluate(
            """
            () => {
                const sels = [
                    '.geetest_btn_click', '.geetest_btn', '.geetest_box_btn',
                    '.embed-captcha button', '.embed-captcha'
                ];
                for (const s of sels) {
                    const el = document.querySelector(s);
                    if (!el) continue;
                    const r = el.getBoundingClientRect();
                    if (r.width > 0 && r.height > 0) {
                        return {
                            x: r.left + r.width / 2,
                            y: r.top + r.height / 2,
                            sel: s
                        };
                    }
                }
                return null;
            }
            """
        )
    except Exception:
        box = None

    if not box:
        return None

    try:
        page.mouse.click(box['x'], box['y'])
        return box['sel']
    except Exception:
        try:
            page.click(box['sel'], timeout=3000, force=True)
            return box['sel']
        except Exception:
            return None


def handle_geetest(page):
    """
    处理 Geetest 验证码：
      True  -> 已确认通过（原生自适应 / 打码 / 人工）
      False -> 未检测到验证码，按原流程继续（兼容旧行为）
      Exception -> 弹出了图形验证码但未能通过
    """
    # 已经通过则直接返回（例如页面缓存了上一次验证结果）
    if _geetest_passed(_geetest_state(page)):
        print('验证码已处于通过状态')
        return True

    # 点击「点我开始验证」
    sel = _click_geetest_button(page)

    if sel:
        print(f'已点击「点我开始验证」：{sel}')
    else:
        print('未找到验证按钮，跳过验证码处理')

    # 等待：原生通过 或 弹出图形验证
    deadline = time.time() + 8

    state = {}

    while time.time() < deadline:

        state = _geetest_state(page)

        if _geetest_passed(state):
            print('验证码已通过（自适应验证，无需识别）')
            _dismiss_geetest_popup(page)
            return True

        if state.get('popupVisible'):
            break

        time.sleep(0.5)

    state = _geetest_state(page) or {}

    if _geetest_passed(state):
        print('验证码已通过')
        _dismiss_geetest_popup(page)
        return True

    if not state.get('popupVisible'):
        print('未检测到图形验证弹窗，按原流程继续')
        return False

    # 弹出图形验证码
    print('检测到图形验证码弹窗（九宫格点选）')

    if CAPTCHA_KEY:

        try:

            captcha_id = state.get('captchaId')

            print(f'提交打码平台识别（{CAPTCHA_PROVIDER}）...')

            result = solve_geetest_v4(captcha_id, page.url)

            _inject_geetest_result(page, result)

            # 确认注入生效
            injected = page.evaluate(
                "() => !!(window.Captcha && window.Captcha.isReady && window.Captcha.isReady())"
            )

            if not injected:
                raise Exception('打码结果注入页面失败')

            print('打码结果已注入，等待站点确认...')

            time.sleep(1)

            _dismiss_geetest_popup(page)

            return True

        except Exception as e:

            print(f'打码失败：{e}')

            if PLAYWRIGHT_HEADLESS:
                raise Exception(f'图形验证码未通过（打码失败：{e}）')

    if not PLAYWRIGHT_HEADLESS:

        print(
            f'请在浏览器中手动完成验证码，最多等待 {CAPTCHA_MANUAL_WAIT} 秒...'
        )

        deadline = time.time() + CAPTCHA_MANUAL_WAIT

        while time.time() < deadline:

            if _geetest_passed(_geetest_state(page)):
                print('人工验证已完成')
                _dismiss_geetest_popup(page)
                return True

            time.sleep(1)

        raise Exception('人工验证超时，图形验证码未通过')

    raise Exception(
        '图形验证码未通过：未配置 CAPTCHA_KEY（打码密钥），'
        '无头模式无法自动识别九宫格验证码。'
        '可配置 CAPTCHA_KEY 自动打码，或设置 PLAYWRIGHT_HEADLESS=0 手动完成验证'
    )


# ─────────────────────────────
# Playwright 登录获取 Cookie
# ─────────────────────────────
def playwright_login(email, passwd):

    safe_email = mask_email(email)

    print(f'\n启动浏览器进行登录：{safe_email}')

    with sync_playwright() as p:

        browser = p.chromium.launch(
            headless=PLAYWRIGHT_HEADLESS,
            args=[
                '--disable-blink-features=AutomationControlled'
            ]
        )

        context = browser.new_context(
            user_agent=USER_AGENT,
            viewport={"width": 1280, "height": 800},
            locale="zh-CN"
        )

        # 隐藏自动化特征
        context.add_init_script("""
            Object.defineProperty(navigator, 'webdriver', {
                get: () => undefined
            });
        """)

        # 注入 Geetest 钩子，记录 captchaId 等参数（供打码使用）
        context.add_init_script(GEETEST_HOOK_JS)

        page = context.new_page()

        # 打开登录页
        page.goto(
            'https://ikuuu.top/auth/login',
            wait_until='networkidle'
        )

        print('填写账号密码...')

        # 输入账号密码
        page.fill('#email', email)
        page.fill('#password', passwd)

        print('点击验证按钮...')

        # 点击 "点我开始验证" 并处理图形验证码（原生自适应 / 打码 / 人工）
        handle_geetest(page)

        print('点击登录按钮...')

        # 点击登录
        page.click('button[type="submit"]')

        # 等待跳转
        time.sleep(5)

        print('获取 Cookie...')

        # 获取浏览器 Cookie
        cookies = context.cookies()

        browser.close()

        return cookies


# ─────────────────────────────
# 单账号签到
# ─────────────────────────────
def checkin_one_account(email, passwd):

    safe_email = mask_email(email)

    check_url = 'https://ikuuu.top/user/checkin'

    header = {
        'origin': 'https://ikuuu.top',
        'user-agent': USER_AGENT
    }

    try:

        # 登录获取 Cookie
        pw_cookies = playwright_login(email, passwd)

        if not pw_cookies:
            raise Exception('未获取到 Cookie')

        print('创建 requests session...')

        session = requests.session()

        # 导入 Cookie
        for c in pw_cookies:

            name = c.get('name')
            value = c.get('value')

            if name and value:
                session.cookies.set(name, value)

        print('开始签到...')

        # requests 执行签到
        result = session.post(
            url=check_url,
            headers=header,
            timeout=20
        ).json()

        print(result)

        content = result.get('msg', '未知结果')

        print(content)

        return f'✅ {safe_email} -> {content}'

    except Exception as e:

        err = f'❌ {safe_email} -> {str(e)}'

        print(err)

        return err


# ─────────────────────────────
# 主函数
# ─────────────────────────────
def handler(event=None, context=None):

    try:

        # 多账号环境变量
        # 格式：
        # aaa@qq.com:123456
        # bbb@qq.com:abcdef

        accounts_str = os.environ.get('ACCOUNTS')

        if not accounts_str:
            raise Exception('未配置 ACCOUNTS 环境变量')

        accounts = []

        for line in accounts_str.strip().splitlines():

            line = line.strip()

            if line and ':' in line:

                email, passwd = line.split(':', 1)

                accounts.append(
                    (email.strip(), passwd.strip())
                )

        if not accounts:
            raise Exception('未读取到账号')

        print(f'\n共发现 {len(accounts)} 个账号')

        all_result = []

        # 逐个账号签到
        for idx, (email, passwd) in enumerate(accounts, 1):

            print('\n' + '=' * 50)
            print(f'开始处理第 {idx} 个账号')
            print('=' * 50)

            result = checkin_one_account(email, passwd)

            all_result.append(result)

        # 汇总结果
        final_msg = '\n'.join(all_result)

        print('\n最终结果：')
        print(final_msg)

        # PushPlus 推送通知
        send_pushplus(
            '[ikuuu] 多账号签到结果',
            final_msg
        )

    except Exception as e:

        content = f'签到失败：{str(e)}'

        print(content)

        send_pushplus(
            '[ikuuu] 签到结果',
            content
        )

    return '任务完成'


if __name__ == "__main__":
    handler()
