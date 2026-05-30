import pytest

from agents.api_key_manager import ApiKeyManager, resolve_key_pool


def test_resolve_key_pool_uses_numbered_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify numbered env keys are loaded into the provider pool."""
    monkeypatch.setenv("GROQ_API_KEY_1", "gsk_test_key_number_one_abc")
    monkeypatch.setenv("GROQ_API_KEY_2", "gsk_test_key_number_two_xyz")
    monkeypatch.delenv("GROQ_API_KEY", raising=False)

    keys = resolve_key_pool("groq")

    assert len(keys) >= 2
    assert "gsk_test_key_number_one_abc" in keys
    assert "gsk_test_key_number_two_xyz" in keys


def test_acquire_key_round_robin(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify acquire_key cycles through all configured keys."""
    for i in range(1, 6):
        monkeypatch.delenv(f"GEMINI_API_KEY_{i}", raising=False)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setenv("GEMINI_API_KEY_1", "gemini_test_key_alpha_12345")
    monkeypatch.setenv("GEMINI_API_KEY_2", "gemini_test_key_beta_67890")
    ApiKeyManager._cursor["gemini"] = 0

    first = ApiKeyManager.acquire_key("gemini")
    second = ApiKeyManager.acquire_key("gemini")
    third = ApiKeyManager.acquire_key("gemini")

    assert first == "gemini_test_key_alpha_12345"
    assert second == "gemini_test_key_beta_67890"
    assert third == "gemini_test_key_alpha_12345"


def test_rotate_advances_to_next_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify rotate returns the next key after the current cursor."""
    monkeypatch.setenv("DEEPSEEK_API_KEY_1", "ds_test_key_one_abcdefghij")
    monkeypatch.setenv("DEEPSEEK_API_KEY_2", "ds_test_key_two_abcdefghij")
    ApiKeyManager._cursor["deepseek"] = 0

    assert ApiKeyManager.acquire_key("deepseek") == "ds_test_key_one_abcdefghij"
    rotated = ApiKeyManager.rotate("deepseek")

    assert rotated == "ds_test_key_two_abcdefghij"


def test_acquire_key_raises_when_no_keys(monkeypatch: pytest.MonkeyPatch) -> None:
    """Verify a clear error is raised when no keys are configured."""
    for i in range(1, 6):
        monkeypatch.delenv(f"GROQ_API_KEY_{i}", raising=False)
    monkeypatch.delenv("GROQ_API_KEY", raising=False)
    ApiKeyManager._cursor["groq"] = 0

    with pytest.raises(ValueError, match="No GROQ API keys found"):
        ApiKeyManager.acquire_key("groq")
