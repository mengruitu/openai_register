# test_oauth.py
import sys
sys.path.insert(0, ".")

from register_app.auth.oauth import submit_callback_url, generate_oauth_url

proxies = {"http": "http://127.0.0.1:7890", "https": "http://127.0.0.1:7890"}

# 先生成一组 OAuth 参数
oauth = generate_oauth_url()
print("授权 URL：")
print(oauth.auth_url)
print()

# 手动在浏览器打开上面的 URL，完成登录后
# 浏览器会跳转到 http://localhost:1455/auth/callback?code=xxx&state=xxx
# 把完整的回调 URL 粘贴到这里：
callback_url = input("请粘贴回调 URL：").strip()

result = submit_callback_url(
    callback_url=callback_url,
    expected_state=oauth.state,
    code_verifier=oauth.code_verifier,
    redirect_uri=oauth.redirect_uri,
    proxies=proxies,
)

print("Token JSON：")
print(result)