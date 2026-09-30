from sentinel_core.models import core as models
from sentinel_core.modules.identity.test_account_secrets import TestAccountSecretCodec
from sentinel_worker.modules.identity.authorization_replay import infer_victim_account


def test_infer_victim_account_matches_encrypted_auth_token_fallback():
    victim = models.TestAccount(
        id="victim",
        account_id=1000000,
        role="ADMIN",
        **TestAccountSecretCodec.encrypt_payload({"auth_headers": {}, "auth_token": "victim-token"}),
    )

    matched = infer_victim_account(
        [victim],
        {"headers": {"Authorization": "Bearer victim-token"}},
    )

    assert matched is victim
