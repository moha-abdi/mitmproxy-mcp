from mitmproxy_mcp.privacy import (
    RedactionEngine,
    init_redaction_engine,
    get_redaction_engine,
    reset_redaction_engine,
    DEFAULT_PATTERNS,
)


class TestRedactionEngine:
    def test_engine_initializes_with_default_patterns(self):
        engine = RedactionEngine()
        assert len(engine.patterns) == len(DEFAULT_PATTERNS)

    def test_engine_adds_custom_patterns(self):
        engine = RedactionEngine(custom_patterns=["my_secret", "another_pattern"])
        assert len(engine.patterns) == len(DEFAULT_PATTERNS) + 2


class TestBearerTokenRedaction:
    def test_bearer_token_redacted(self):
        engine = RedactionEngine()
        text = "Authorization: Bearer abc123xyz789"
        result = engine.redact_string(text)
        assert "Bearer [REDACTED]" in result
        assert "abc123xyz789" not in result

    def test_bearer_token_with_special_chars(self):
        engine = RedactionEngine()
        text = "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test"
        result = engine.redact_string(text)
        assert "[REDACTED]" in result

    def test_bearer_case_insensitive(self):
        engine = RedactionEngine()
        text = "BEARER secret123"
        result = engine.redact_string(text)
        assert "Bearer [REDACTED]" in result
        assert "secret123" not in result


class TestBasicAuthRedaction:
    def test_basic_auth_redacted(self):
        engine = RedactionEngine()
        text = "Authorization: Basic dXNlcjpwYXNz"
        result = engine.redact_string(text)
        assert "Basic [REDACTED]" in result
        assert "dXNlcjpwYXNz" not in result


class TestAPIKeyRedaction:
    def test_api_key_header_redacted(self):
        engine = RedactionEngine()
        text = "X-API-Key: secret123key"
        result = engine.redact_string(text)
        assert "[REDACTED]" in result
        assert "secret123key" not in result

    def test_api_key_query_param_redacted(self):
        engine = RedactionEngine()
        text = "api_key=mysecretapikey"
        result = engine.redact_string(text)
        assert "[REDACTED]" in result
        assert "mysecretapikey" not in result

    def test_apikey_no_underscore(self):
        engine = RedactionEngine()
        text = "apikey=mykey123"
        result = engine.redact_string(text)
        assert "[REDACTED]" in result
        assert "mykey123" not in result


class TestPasswordRedaction:
    def test_password_redacted(self):
        engine = RedactionEngine()
        text = "password=supersecret123"
        result = engine.redact_string(text)
        assert "password=[REDACTED]" in result
        assert "supersecret123" not in result

    def test_passwd_redacted(self):
        engine = RedactionEngine()
        text = "passwd: mypass"
        result = engine.redact_string(text)
        assert "[REDACTED]" in result
        assert "mypass" not in result

    def test_secret_redacted(self):
        engine = RedactionEngine()
        text = "secret=confidential_value"
        result = engine.redact_string(text)
        assert "[REDACTED]" in result
        assert "confidential_value" not in result


class TestJWTRedaction:
    def test_jwt_redacted(self):
        engine = RedactionEngine()
        jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
        text = f"Token: {jwt}"
        result = engine.redact_string(text)
        assert "[REDACTED_JWT]" in result
        assert "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9" not in result

    def test_jwt_in_authorization_header(self):
        engine = RedactionEngine()
        jwt = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.abc123"
        text = f"Bearer {jwt}"
        result = engine.redact_string(text)
        assert "[REDACTED" in result
        assert "eyJhbGciOiJIUzI1NiJ9" not in result


class TestSessionIDRedaction:
    def test_session_id_redacted(self):
        engine = RedactionEngine()
        text = "session_id=abc123session456"
        result = engine.redact_string(text)
        assert "[REDACTED]" in result
        assert "abc123session456" not in result

    def test_jsessionid_redacted(self):
        engine = RedactionEngine()
        text = "JSESSIONID=ABCD1234EFGH5678"
        result = engine.redact_string(text)
        assert "[REDACTED]" in result
        assert "ABCD1234EFGH5678" not in result

    def test_sid_redacted(self):
        engine = RedactionEngine()
        text = "sid=mysession123"
        result = engine.redact_string(text)
        assert "[REDACTED]" in result
        assert "mysession123" not in result


class TestAccessTokenRedaction:
    def test_access_token_redacted(self):
        engine = RedactionEngine()
        text = "access_token=mytoken123"
        result = engine.redact_string(text)
        assert "[REDACTED]" in result
        assert "mytoken123" not in result

    def test_auth_token_redacted(self):
        engine = RedactionEngine()
        text = "auth_token=secret456"
        result = engine.redact_string(text)
        assert "[REDACTED]" in result
        assert "secret456" not in result


class TestCookieRedaction:
    def test_connect_sid_redacted(self):
        engine = RedactionEngine()
        text = "connect.sid=s%3Aabcd1234.signature"
        result = engine.redact_string(text)
        assert "[REDACTED]" in result
        assert "abcd1234" not in result


class TestCustomPatterns:
    def test_custom_pattern_redacts(self):
        engine = RedactionEngine(custom_patterns=[r"my_custom_secret_\d+"])
        text = "Found my_custom_secret_12345 in data"
        result = engine.redact_string(text)
        assert "[REDACTED]" in result
        assert "my_custom_secret_12345" not in result

    def test_multiple_custom_patterns(self):
        engine = RedactionEngine(custom_patterns=["internal_token", "private_key"])
        text = "internal_token=abc private_key=xyz"
        result = engine.redact_string(text)
        assert result.count("[REDACTED]") == 2


class TestRedactString:
    def test_none_returns_none(self):
        engine = RedactionEngine()
        assert engine.redact_string(None) is None

    def test_empty_returns_empty(self):
        engine = RedactionEngine()
        assert engine.redact_string("") == ""

    def test_no_sensitive_data_unchanged(self):
        engine = RedactionEngine()
        text = "Hello, this is normal text"
        assert engine.redact_string(text) == text

    def test_multiple_sensitive_items_in_string(self):
        engine = RedactionEngine()
        text = "api_key=secret1 password=secret2"
        result = engine.redact_string(text)
        assert "secret1" not in result
        assert "secret2" not in result
        assert result.count("[REDACTED]") == 2


class TestRedactDict:
    def test_redact_dict_headers(self):
        engine = RedactionEngine()
        headers = {
            "Authorization": "Bearer secret123",
            "Content-Type": "application/json",
            "X-API-Key": "mysecretkey",
        }
        result = engine.redact_dict(headers, is_headers=True)
        assert "secret123" not in result["Authorization"]
        assert "mysecretkey" not in result["X-API-Key"]
        assert result["Content-Type"] == "application/json"

    def test_redact_empty_dict(self):
        engine = RedactionEngine()
        assert engine.redact_dict({}) == {}

    def test_redact_none_dict(self):
        engine = RedactionEngine()
        assert engine.redact_dict(None) is None


class TestRedactFlowDetail:
    def test_redact_request_headers(self):
        engine = RedactionEngine()
        flow_detail = {
            "id": "flow-123",
            "request": {
                "method": "GET",
                "url": "http://example.com",
                "headers": {"Authorization": "Bearer token123"},
                "body": None,
            },
            "response": None,
        }
        result = engine.redact_flow_detail(flow_detail)
        assert "token123" not in str(result)
        assert "[REDACTED]" in result["request"]["headers"]["Authorization"]

    def test_redact_request_body(self):
        engine = RedactionEngine()
        flow_detail = {
            "request": {
                "body": '{"password": "secret123", "user": "test"}',
                "headers": {},
                "url": "http://example.com",
            },
            "response": None,
        }
        result = engine.redact_flow_detail(flow_detail)
        assert "secret123" not in result["request"]["body"]

    def test_redact_request_url_query_params(self):
        engine = RedactionEngine()
        flow_detail = {
            "request": {
                "url": "http://example.com/api?api_key=secret123&name=test",
                "headers": {},
                "body": None,
            },
            "response": None,
        }
        result = engine.redact_flow_detail(flow_detail)
        assert "secret123" not in result["request"]["url"]

    def test_redact_response_headers(self):
        engine = RedactionEngine()
        flow_detail = {
            "request": {"headers": {}, "url": "http://example.com", "body": None},
            "response": {
                "headers": {"Set-Cookie": "session_id=abc123"},
                "body": None,
            },
        }
        result = engine.redact_flow_detail(flow_detail)
        assert "abc123" not in str(result)

    def test_redact_response_body(self):
        engine = RedactionEngine()
        flow_detail = {
            "request": {"headers": {}, "url": "http://example.com", "body": None},
            "response": {
                "headers": {},
                "body": '{"access_token": "mytoken456"}',
            },
        }
        result = engine.redact_flow_detail(flow_detail)
        assert "mytoken456" not in result["response"]["body"]


class TestRedactFlowSummary:
    def test_redact_url_with_token(self):
        engine = RedactionEngine()
        summary = {
            "id": "flow-1",
            "method": "GET",
            "url": "http://api.example.com?access_token=secret123",
            "status_code": 200,
        }
        result = engine.redact_flow_summary(summary)
        assert "secret123" not in result["url"]


class TestRedactHAREntry:
    def test_redact_har_request_url(self):
        engine = RedactionEngine()
        entry = {
            "request": {
                "url": "http://example.com?api_key=secret123",
                "headers": [],
                "queryString": [],
            },
            "response": {"headers": [], "content": {}},
        }
        result = engine.redact_har_entry(entry)
        assert "secret123" not in result["request"]["url"]

    def test_redact_har_request_headers(self):
        engine = RedactionEngine()
        entry = {
            "request": {
                "url": "http://example.com",
                "headers": [
                    {"name": "Authorization", "value": "Bearer abc123"},
                    {"name": "Content-Type", "value": "application/json"},
                ],
                "queryString": [],
            },
            "response": {"headers": [], "content": {}},
        }
        result = engine.redact_har_entry(entry)
        assert "abc123" not in result["request"]["headers"][0]["value"]
        assert result["request"]["headers"][1]["value"] == "application/json"

    def test_redact_har_query_string(self):
        engine = RedactionEngine()
        entry = {
            "request": {
                "url": "http://example.com",
                "headers": [],
                "queryString": [
                    {"name": "api_key", "value": "secret123"},
                    {"name": "name", "value": "test"},
                ],
            },
            "response": {"headers": [], "content": {}},
        }
        result = engine.redact_har_entry(entry)
        assert "secret123" not in result["request"]["queryString"][0]["value"]

    def test_redact_har_post_data(self):
        engine = RedactionEngine()
        entry = {
            "request": {
                "url": "http://example.com",
                "headers": [],
                "queryString": [],
                "postData": {"text": "password=secret123"},
            },
            "response": {"headers": [], "content": {}},
        }
        result = engine.redact_har_entry(entry)
        assert "secret123" not in result["request"]["postData"]["text"]

    def test_redact_har_response_headers(self):
        engine = RedactionEngine()
        entry = {
            "request": {"url": "http://example.com", "headers": [], "queryString": []},
            "response": {
                "headers": [{"name": "Set-Cookie", "value": "session_id=xyz789"}],
                "content": {},
            },
        }
        result = engine.redact_har_entry(entry)
        assert "xyz789" not in result["response"]["headers"][0]["value"]

    def test_redact_har_response_content(self):
        engine = RedactionEngine()
        entry = {
            "request": {"url": "http://example.com", "headers": [], "queryString": []},
            "response": {
                "headers": [],
                "content": {"text": '{"token": "Bearer secret_token"}'},
            },
        }
        result = engine.redact_har_entry(entry)
        assert "secret_token" not in result["response"]["content"]["text"]


class TestGlobalRedactionEngine:
    def setup_method(self):
        reset_redaction_engine()

    def teardown_method(self):
        reset_redaction_engine()

    def test_get_engine_returns_none_before_init(self):
        assert get_redaction_engine() is None

    def test_init_creates_engine(self):
        init_redaction_engine()
        engine = get_redaction_engine()
        assert engine is not None
        assert isinstance(engine, RedactionEngine)

    def test_init_with_custom_patterns(self):
        init_redaction_engine(custom_patterns=["my_pattern"])
        engine = get_redaction_engine()
        assert len(engine.patterns) == len(DEFAULT_PATTERNS) + 1

    def test_reset_clears_engine(self):
        init_redaction_engine()
        assert get_redaction_engine() is not None
        reset_redaction_engine()
        assert get_redaction_engine() is None
