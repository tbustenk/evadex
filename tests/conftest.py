import pytest
from evadex.core.result import Payload, PayloadCategory, Variant
from evadex.core.registry import load_builtins


@pytest.fixture(autouse=True, scope="session")
def load_all_builtins():
    load_builtins()


@pytest.fixture
def visa_payload():
    return Payload("4532015112830366", PayloadCategory.CREDIT_CARD, "Visa 16-digit")


@pytest.fixture
def ssn_payload():
    return Payload("123-45-6789", PayloadCategory.SSN, "US SSN")


@pytest.fixture
def email_payload():
    return Payload("test.user@example.com", PayloadCategory.EMAIL, "Email address")
