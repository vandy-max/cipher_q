import pytest

from authentication.password import generate_salt, hash_password, verify_password


def test_same_password_and_salt_give_same_hash():
    salt = generate_salt()
    assert hash_password("correct horse battery staple", salt) == hash_password(
        "correct horse battery staple", salt
    )


def test_different_salt_gives_different_hash():
    h1 = hash_password("same-password", generate_salt())
    h2 = hash_password("same-password", generate_salt())
    assert h1 != h2


def test_verify_password_round_trip():
    salt = generate_salt()
    stored_hash = hash_password("hunter2", salt)
    assert verify_password("hunter2", salt, stored_hash)
    assert not verify_password("wrong-password", salt, stored_hash)


def test_empty_password_rejected():
    with pytest.raises(ValueError):
        hash_password("", generate_salt())
