//! Codes B and C: OPAQUE registration and login with opaque-ke, both parties in one process.
//! Every "->" comment is a network message in a real deployment.
use opaque_examples::{ksf, Suite, CONTEXT};
use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration, ClientRegistrationFinishParameters,
    Identifiers, ServerLogin, ServerLoginParameters, ServerRegistration, ServerSetup,
};
use rand_core::OsRng;

const IDS: Identifiers = Identifiers { client: Some(b"alice"), server: Some(b"example.com") };

// ---- Code B: registration --------------------------------------------------
fn register(setup: &ServerSetup<Suite>, password: &[u8]) -> ServerRegistration<Suite> {
    let client = ClientRegistration::<Suite>::start(&mut OsRng, password).unwrap(); // -> request
    let server = ServerRegistration::start(setup, client.message, b"alice").unwrap(); // <- response
    let k = ksf();
    let upload = client
        .state
        .finish(&mut OsRng, password, server.message, ClientRegistrationFinishParameters::new(IDS, Some(&k)))
        .unwrap(); // -> record
    ServerRegistration::finish(upload.message) // the server stores this
}

// ---- Code C: login ---------------------------------------------------------
fn login(setup: &ServerSetup<Suite>, password: &[u8], record: &ServerRegistration<Suite>) -> bool {
    let params = || ServerLoginParameters { context: Some(CONTEXT), identifiers: IDS };
    let client = ClientLogin::<Suite>::start(&mut OsRng, password).unwrap(); // -> KE1
    let server =
        ServerLogin::start(&mut OsRng, setup, Some(record.clone()), client.message, b"alice", params()).unwrap(); // <- KE2

    // A wrong password fails here: the server MAC in KE2 does not verify.
    let k = ksf();
    let Ok(done) = client.state.finish(
        &mut OsRng,
        password,
        server.message,
        ClientLoginFinishParameters::new(Some(CONTEXT), IDS, Some(&k)),
    ) else {
        return false;
    }; // -> KE3

    let Ok(server_done) = server.state.finish(done.message, params()) else { return false };
    assert_eq!(done.session_key, server_done.session_key);
    // done.export_key: a client-only key for encrypting extra data; the server never sees it.
    true
}

fn main() {
    let setup = ServerSetup::<Suite>::new(&mut OsRng); // server: long-term keys + OPRF seed
    let record = register(&setup, b"correct horse battery staple");
    println!("stored record: {} bytes", record.serialize().len());
    for attempt in ["correct horse battery staple", "correct horse battery stapler"] {
        let ok = login(&setup, attempt.as_bytes(), &record);
        println!("'{attempt}': user {}", if ok { "authenticated" } else { "NOT authenticated" });
    }
}
