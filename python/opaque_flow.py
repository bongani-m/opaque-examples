"""Codes B and C: OPAQUE registration and login with libopaque.

Both parties run in one process so the flow reads top to bottom. In a real
deployment every `# ->` line is a network message (see server.py).
"""
import opaque

CONTEXT = b"opaque-examples-v1"          # bind the protocol to this app
IDS = opaque.Ids("alice", "example.com")  # idU, idS


# --- Code B: registration -------------------------------------------------
def register(password: str) -> bytes:
    # Client: blind the password. The server never sees it.
    client_sec, request = opaque.CreateRegistrationRequest(password)
    # -> request

    # Server: evaluate the OPRF with a fresh per-user key.
    server_sec, response = opaque.CreateRegistrationResponse(request)
    # <- response

    # Client: unblind, harden (Argon2id), seal the envelope.
    reg_record, export_key = opaque.FinalizeRequest(client_sec, response, IDS)
    # -> reg_record

    # Server: store this. It holds no password and no password hash.
    return opaque.StoreUserRecord(server_sec, reg_record)


# --- Code C: login ---------------------------------------------------------
def login(password: str, record: bytes) -> bool:
    # Client: KE1 = blinded password + nonce + ephemeral key share.
    ke1, client_sec = opaque.CreateCredentialRequest(password)
    # -> ke1

    # Server: KE2 = OPRF evaluation + masked envelope + its key share + MAC.
    ke2, server_session_key, server_auth_state = opaque.CreateCredentialResponse(
        ke1, record, IDS, CONTEXT)
    # <- ke2

    # Client: open the envelope. A wrong password fails *here*, on the
    # server MAC check inside RecoverCredentials, not on a string compare.
    try:
        client_session_key, ke3, export_key = opaque.RecoverCredentials(
            ke2, client_sec, CONTEXT, IDS)
    except ValueError:
        return False
    # -> ke3

    # Server: check the client's MAC. Both sides now share a session key.
    try:
        opaque.UserAuth(server_auth_state, ke3)
    except ValueError:
        return False
    assert client_session_key == server_session_key
    return True


if __name__ == "__main__":
    record = register("correct horse battery staple")
    print("stored record:", len(record), "bytes")
    for attempt in ("correct horse battery staple", "correct horse battery stapler"):
        ok = login(attempt, record)
        print(f"{attempt!r}: user {'authenticated' if ok else 'NOT authenticated'}")
