// Codes B and C: OPAQUE registration and login with libopaque, both parties in
// one process. Every "->" comment is a network message in a real deployment.
#include "opaque.hpp"

#include <cstdio>
#include <string>

constexpr std::string_view kContext = "opaque-examples-v1";
const op::Ids kIds{"alice", "example.com"};

// ---- Code B: registration -------------------------------------------------
op::Bytes register_user(std::string_view password) {
    auto client = op::create_registration_request(password);          // -> request
    auto server = op::create_registration_response(client.request);   // <- response
    auto fin = op::finalize_request(client.sec, server.response, kIds);  // -> record
    return op::store_user_record(server.sec, fin.record);             // server stores this
}

// ---- Code C: login --------------------------------------------------------
bool login(std::string_view password, const op::Bytes& record) {
    auto client = op::create_credential_request(password);            // -> KE1
    auto server = op::create_credential_response(client.ke1, record, kIds, kContext);  // <- KE2
    try {
        auto rec = op::recover_credentials(server.ke2, client.sec, kContext, kIds);    // -> KE3
        if (!op::user_auth(server.expected_ke3, rec.ke3)) return false;
        return sodium_memcmp(rec.session_key.data(), server.session_key.data(),
                             rec.session_key.size()) == 0;
    } catch (const op::Error&) {
        return false;  // wrong password: KE2's MAC did not verify
    }
}

int main() {
    if (sodium_init() < 0) return 1;
    const auto record = register_user("correct horse battery staple");
    std::printf("stored record: %zu bytes\n", record.size());
    for (const char* attempt : {"correct horse battery staple", "correct horse battery stapler"}) {
        std::printf("'%s': user %s\n", attempt, login(attempt, record) ? "authenticated" : "NOT authenticated");
    }
}
