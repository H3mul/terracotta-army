import pytest

from terracotta_general.requests import APPROVAL_WINDOW, RequestStore, State, TransitionError


class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


@pytest.fixture
def clk():
    return Clock()


@pytest.fixture
def store(clk):
    return RequestStore(clk)


def test_approve_then_active_then_expires(store, clk):
    r = store.create("Octo/App", "write", 600)
    assert r.repo == "octo/app" and r.state is State.PENDING
    store.approve(r.id)
    assert [x.id for x in store.active("octo/app", "write")] == [r.id]
    clk.t += 599
    assert store.active()
    clk.t += 2
    assert store.get(r.id).state is State.EXPIRED
    assert not store.active()


def test_pending_expires_unapproved_and_cannot_be_approved(store, clk):
    r = store.create("o/r", "read", 60)
    clk.t += APPROVAL_WINDOW
    assert store.get(r.id).state is State.EXPIRED
    with pytest.raises(TransitionError):
        store.approve(r.id)


def test_approve_only_once(store):
    r = store.create("o/r", "read", 60)
    store.approve(r.id)
    with pytest.raises(TransitionError):
        store.approve(r.id)


def test_revoke(store):
    r = store.create("o/r", "write", 60)
    store.approve(r.id)
    assert store.revoke(r.id).state is State.REVOKED
    assert not store.active()
    with pytest.raises(TransitionError):
        store.revoke(r.id)  # nothing left to revoke


def test_unknown_id(store):
    with pytest.raises(TransitionError):
        store.get("nope")


def test_active_filters(store):
    a = store.create("o/a", "read", 60)
    b = store.create("o/b", "write", 60)
    store.approve(a.id)
    store.approve(b.id)
    assert [r.repo for r in store.active(level="write")] == ["o/b"]
    assert [r.repo for r in store.active(repo="O/A")] == ["o/a"]
