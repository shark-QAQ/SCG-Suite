"""
测试扫描器功能
"""
from scg.rules.builtin import scan_code_content

def test_hardcoded_password_detected():
    code = 'password = "secret123"'
    issues = scan_code_content(code)
    assert len(issues) == 1
    assert issues[0].rule_id == "SCG-001"
    assert issues[0].severity == "high"

def test_safe_code_passes():
    code = 'print("hello world")'
    issues = scan_code_content(code)
    assert len(issues) == 0

def test_dangerous_bash_command():
    code = 'rm -rf /'
    issues = scan_code_content(code, language="bash")
    assert any(i.rule_id == "SCG-002" for i in issues)


def test_hardcoded_token_and_yaml_style_detected():
    assert scan_code_content('token = "abc123"')[0].rule_id == "SCG-001"
    assert scan_code_content('api_key = "abc123"')[0].rule_id == "SCG-001"
    assert scan_code_content('password: "abc123"', language="unknown")[0].rule_id == "SCG-001"
    assert scan_code_content('{"password": "abc123"}', language="unknown")[0].rule_id == "SCG-001"


def test_password_comparison_is_not_flagged():
    assert scan_code_content('if password == "secret123": pass') == []
    assert scan_code_content('if token != "secret123": pass') == []


def test_environment_placeholder_is_not_flagged():
    assert scan_code_content('password = "${DB_PASSWORD}"') == []
    assert scan_code_content('password = os.environ["DB_PASSWORD"]') == []


def test_sql_injection_by_concatenation_detected():
    code = 'query = "SELECT * FROM users WHERE id = " + user_id'
    issues = scan_code_content(code, language="python")
    assert [i.rule_id for i in issues] == ["SCG-003"]


def test_sql_injection_by_fstring_detected():
    code = 'query = f"SELECT * FROM users WHERE id = {user_id}"'
    issues = scan_code_content(code, language="python")
    assert [i.rule_id for i in issues] == ["SCG-003"]


def test_parameterized_query_is_not_flagged():
    code = 'cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))'
    assert scan_code_content(code, language="python") == []


def test_dangerous_bash_command_variants():
    for code in [
        'rm -rf /',
        'rm -fr /',
        'rm -r -f /',
        'rm --recursive --force /',
        'mkfs /dev/sda',
        'mkfs.ext4 /dev/sda1',
        'dd if=/dev/zero of=/dev/sda',
    ]:
        issues = scan_code_content(code, language="bash")
        assert any(i.rule_id == "SCG-002" for i in issues), code


def test_relative_rm_is_not_flagged():
    assert scan_code_content('rm -rf ./dist', language="bash") == []


def test_bash_rule_is_language_specific():
    assert scan_code_content('rm -rf /', language="python") == []
