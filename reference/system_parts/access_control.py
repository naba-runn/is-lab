# Time-limited, revocable access (DRM style): access is per (user, resource),
# it expires after a duration, and it can be revoked early.
#
# Call your decrypt function only after is_access_valid() returns True.

from datetime import datetime, timedelta

grants = {}     # (user, content) -> {"expires_at": datetime, "revoked": bool}


def grant_access(user, content, duration_hours):
    grants[(user, content)] = {
        "expires_at": datetime.now() + timedelta(hours=duration_hours),
        "revoked": False,
    }


def revoke_access(user, content):
    if (user, content) in grants:
        grants[(user, content)]["revoked"] = True


def is_access_valid(user, content):
    grant = grants.get((user, content))
    if not grant or grant["revoked"]:
        return False

    return datetime.now() < grant["expires_at"]


def is_owner_or_valid(user, content, owner):
    """Content creators always manage their own content."""
    return user == owner or is_access_valid(user, content)


if __name__ == "__main__":
    grant_access("alice", "movie-1", duration_hours=48)
    print("alice, just granted :", is_access_valid("alice", "movie-1"))
    print("bob, never granted  :", is_access_valid("bob", "movie-1"))

    revoke_access("alice", "movie-1")
    print("alice, after revoke :", is_access_valid("alice", "movie-1"))

    grant_access("carol", "movie-2", duration_hours=-1)      # already expired
    print("carol, expired      :", is_access_valid("carol", "movie-2"))
    print("creator is always ok:", is_owner_or_valid("dave", "movie-3", owner="dave"))
