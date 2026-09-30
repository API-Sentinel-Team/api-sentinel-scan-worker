from sentinel_worker.modules.test_executor.request_mutator import RequestMutator


def test_role_token_modify_header_becomes_authorization_header():
    request = {
        "method": "GET",
        "url": "https://api.example.com/admin",
        "headers": {"Authorization": "Bearer victim-token", "Accept": "application/json"},
    }
    mutated = RequestMutator().mutate(
        request,
        {"modify_header": {"Bearer member-token": "1"}},
        auth_context={"auth_header": "Authorization"},
    )

    assert mutated["headers"]["Authorization"] == "Bearer member-token"
    assert "Bearer member-token" not in mutated["headers"]
    assert mutated["headers"]["Accept"] == "application/json"
