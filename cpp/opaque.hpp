// A thin C++ wrapper around libopaque's C API: owned buffers, secrets wiped
// on destruction, and exceptions instead of return codes.
#pragma once

#include <sodium.h>
extern "C" {
#include <opaque.h>
}

#include <array>
#include <cstdint>
#include <stdexcept>
#include <string_view>
#include <vector>

namespace op {

using Bytes = std::vector<uint8_t>;

// A byte buffer that is zeroed when it goes out of scope.
struct Secret : Bytes {
    using Bytes::Bytes;
    Secret(const Secret&) = delete;
    Secret& operator=(const Secret&) = delete;
    Secret(Secret&&) = default;
    Secret& operator=(Secret&&) = default;
    ~Secret() { sodium_memzero(data(), size()); }
};

struct Error : std::runtime_error {
    using std::runtime_error::runtime_error;
};

inline void check(int rc, const char* what) {
    if (rc != 0) throw Error(what);
}

inline const uint8_t* u8(std::string_view s) { return reinterpret_cast<const uint8_t*>(s.data()); }

// Identities are bound into the envelope and the transcript.
struct Ids {
    std::string_view user, server;
    Opaque_Ids raw() const {
        return {static_cast<uint16_t>(user.size()), const_cast<uint8_t*>(u8(user)),
                static_cast<uint16_t>(server.size()), const_cast<uint8_t*>(u8(server))};
    }
};

// ---- Registration ---------------------------------------------------------

struct RegistrationRequest { Secret sec; Bytes request; };

inline RegistrationRequest create_registration_request(std::string_view pwd) {
    RegistrationRequest r{Secret(OPAQUE_REGISTER_USER_SEC_LEN + pwd.size()),
                          Bytes(crypto_core_ristretto255_BYTES)};
    check(opaque_CreateRegistrationRequest(u8(pwd), pwd.size(), r.sec.data(), r.request.data()),
          "CreateRegistrationRequest");
    return r;
}

struct RegistrationResponse { Secret sec; Bytes response; };

inline RegistrationResponse create_registration_response(const Bytes& request) {
    RegistrationResponse r{Secret(OPAQUE_REGISTER_SECRET_LEN), Bytes(OPAQUE_REGISTER_PUBLIC_LEN)};
    check(opaque_CreateRegistrationResponse(request.data(), nullptr, r.sec.data(), r.response.data()),
          "CreateRegistrationResponse");
    return r;
}

struct Finalized { Bytes record; Secret export_key; };

inline Finalized finalize_request(const Secret& client_sec, const Bytes& response, const Ids& ids) {
    Finalized f{Bytes(OPAQUE_REGISTRATION_RECORD_LEN), Secret(crypto_hash_sha512_BYTES)};
    Opaque_Ids raw = ids.raw();
    check(opaque_FinalizeRequest(client_sec.data(), response.data(), &raw, f.record.data(),
                                 f.export_key.data()),
          "FinalizeRequest");
    return f;
}

inline Bytes store_user_record(const Secret& server_sec, const Bytes& reg_record) {
    Bytes rec(OPAQUE_USER_RECORD_LEN);
    opaque_StoreUserRecord(server_sec.data(), reg_record.data(), rec.data());
    return rec;
}

// ---- Login ----------------------------------------------------------------

struct CredentialRequest { Secret sec; Bytes ke1; };

inline CredentialRequest create_credential_request(std::string_view pwd) {
    CredentialRequest r{Secret(OPAQUE_USER_SESSION_SECRET_LEN + pwd.size()),
                        Bytes(OPAQUE_USER_SESSION_PUBLIC_LEN)};
    check(opaque_CreateCredentialRequest(u8(pwd), pwd.size(), r.sec.data(), r.ke1.data()),
          "CreateCredentialRequest");
    return r;
}

struct CredentialResponse { Bytes ke2; Secret session_key; Secret expected_ke3; };

inline CredentialResponse create_credential_response(const Bytes& ke1, const Bytes& record,
                                                     const Ids& ids, std::string_view ctx) {
    CredentialResponse r{Bytes(OPAQUE_SERVER_SESSION_LEN), Secret(OPAQUE_SHARED_SECRETBYTES),
                         Secret(crypto_auth_hmacsha512_BYTES)};
    Opaque_Ids raw = ids.raw();
    check(opaque_CreateCredentialResponse(ke1.data(), record.data(), &raw, u8(ctx), ctx.size(),
                                          r.ke2.data(), r.session_key.data(), r.expected_ke3.data()),
          "CreateCredentialResponse");
    return r;
}

struct Recovered { Secret session_key; Bytes ke3; Secret export_key; };

// Throws op::Error when the password is wrong: the server's MAC in KE2 fails.
inline Recovered recover_credentials(const Bytes& ke2, const Secret& client_sec, std::string_view ctx,
                                     const Ids& ids) {
    Recovered r{Secret(OPAQUE_SHARED_SECRETBYTES), Bytes(crypto_auth_hmacsha512_BYTES),
                Secret(crypto_hash_sha512_BYTES)};
    Opaque_Ids raw = ids.raw();
    check(opaque_RecoverCredentials(ke2.data(), client_sec.data(), u8(ctx), ctx.size(), &raw,
                                    r.session_key.data(), r.ke3.data(), r.export_key.data()),
          "RecoverCredentials");
    return r;
}

inline bool user_auth(const Secret& expected_ke3, const Bytes& ke3) {
    return ke3.size() == crypto_auth_hmacsha512_BYTES &&
           opaque_UserAuth(expected_ke3.data(), ke3.data()) == 0;
}

}  // namespace op
