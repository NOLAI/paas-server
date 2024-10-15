import * as libpep from "./libpep.js";
import {
    BlindedGlobalSecretKey,
    DataPoint,
    ElGamal,
    EncryptedDataPoint,
    EncryptedPseudonym,
    GroupElement,
    PEPClient,
    Pseudonym,
    ScalarNonZero,
    SessionKeyShare
} from "./libpep.js";

document.addEventListener('DOMContentLoaded', async () => {
    try {
        await libpep.default();
    } catch (e) {
        console.error("Error in libpep", e);
    }

    const BLINDING_SECRET_PEP = new BlindedGlobalSecretKey(ScalarNonZero.fromHex(document.getElementById("blinded_global_secret_key").value));

    class TranscryptorClient {

        constructor(url, auth_token) {
            this.url = url;
            this.auth_token = auth_token;
            this.system_id = null;
            this.status = {
                state: 'unknown', last_checked: Date.now()
            };
        }

        async check_status() {
            let response = await fetch(this.url + '/status').catch(err => {
                this.status = {
                    state: 'error', last_checked: Date.now()
                }
                return err;
            });

            if (!response.ok) {
                this.status = {
                    state: response.status === 404 ? 'offline' : 'error', last_checked: Date.now()
                }
                return
            }
            let data = await response.json();
            this.status = {
                state: 'online', last_checked: Date.now()
            }
            this.system_id = data.system_id;
        }

        async start_session() {
            let response = await fetch(this.url + '/start_session', {
                method: 'POST',
                mode: 'cors',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer ' + this.auth_token
                }
            }).catch(err => {
                this.status = {
                    state: 'error', last_checked: Date.now()
                }
                return err;
            });

            if (response.ok) {
                return await response.json();
            }
        }

        async pseudonymize(encrypted_pseudonym, pseudonym_context_from, pseudonym_context_to, enc_context, dec_context) {
            let response = await fetch(this.url + '/pseudonymize', {
                method: 'POST',
                mode: 'cors',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer ' + this.auth_token
                },
                body: JSON.stringify({
                    encrypted_pseudonym,
                    pseudonym_context_from, pseudonym_context_to,
                    enc_context, dec_context
                })
            }).catch(err => {
                this.status = {
                    state: 'error', last_checked: Date.now()
                }
                return err;
            });

            if (response.ok) {
                return await response.json();
            }

        }

        async get_sessions(username = null) {
            let response = await fetch(`${this.url}/get_sessions${username ? "/" + username : ""}`, {
                method: 'GET',
                mode: 'cors',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer ' + this.auth_token
                },
            }).catch(err => {
                this.status = {
                    state: 'error', last_checked: Date.now()
                }
                return err;
            });

            if (response.ok) {
                return await response.json();
            }
        }
    }

    let sender_transcryptor_1 = new TranscryptorClient(document.getElementById("transcryptor_1_url").value, document.getElementById("transcryptor_1_sender_token").value);
    let sender_transcryptor_2 = new TranscryptorClient(document.getElementById("transcryptor_2_url").value, document.getElementById("transcryptor_2_sender_token").value);
    let sender_transcryptor_3 = new TranscryptorClient(document.getElementById("transcryptor_3_url").value, document.getElementById("transcryptor_3_sender_token").value);

    let receiver_transcryptor_1 = new TranscryptorClient(document.getElementById("transcryptor_1_url").value, document.getElementById("transcryptor_1_receiver_token").value);
    let receiver_transcryptor_2 = new TranscryptorClient(document.getElementById("transcryptor_2_url").value, document.getElementById("transcryptor_2_receiver_token").value);
    let receiver_transcryptor_3 = new TranscryptorClient(document.getElementById("transcryptor_3_url").value, document.getElementById("transcryptor_3_receiver_token").value);

    let PEPSenderClient = null;
    let PEPReceiverClient = null;

    document.getElementById("sender_start_session_1").addEventListener('submit', async (event) => {
        event.preventDefault();
        let response = await sender_transcryptor_1.start_session();
        document.getElementById("transcryptor_1_sender_sks").value = response.key_share;
        document.getElementById("transcryptor_1_sender_session_id").value = response.session_id;
        updateSenderSessionKey();
    });
    document.getElementById("sender_start_session_2").addEventListener('submit', async (event) => {
        event.preventDefault();
        let response = await sender_transcryptor_2.start_session();
        document.getElementById("transcryptor_2_sender_sks").value = response.key_share;
        document.getElementById("transcryptor_2_sender_session_id").value = response.session_id;
        updateSenderSessionKey();

    });
    document.getElementById("sender_start_session_3").addEventListener('submit', async (event) => {
        event.preventDefault();
        let response = await sender_transcryptor_3.start_session();
        document.getElementById("transcryptor_3_sender_sks").value = response.key_share;
        document.getElementById("transcryptor_3_sender_session_id").value = response.session_id;
        updateSenderSessionKey();
    });

    function updateSenderSessionKey() {
        let sks = [];

        try {
            sks.push(new SessionKeyShare(ScalarNonZero.fromHex(document.getElementById("transcryptor_1_sender_sks").value)));
            sks.push(new SessionKeyShare(ScalarNonZero.fromHex(document.getElementById("transcryptor_2_sender_sks").value)));
            sks.push(new SessionKeyShare(ScalarNonZero.fromHex(document.getElementById("transcryptor_3_sender_sks").value)));
        } catch(err) {
            return
        }

        PEPSenderClient = new PEPClient(BLINDING_SECRET_PEP, sks);
        document.getElementById("sender_session_key").value = "Established";
    }

    document.getElementById("receiver_start_session_1").addEventListener('submit', async (event) => {
        event.preventDefault();
        let response = await receiver_transcryptor_1.start_session();
        document.getElementById("transcryptor_1_receiver_sks").value = response.key_share;
        document.getElementById("transcryptor_1_receiver_session_id").value = response.session_id;
        updateReceiverSessionKey();
    });
    document.getElementById("receiver_start_session_2").addEventListener('submit', async (event) => {
        event.preventDefault();
        let response = await receiver_transcryptor_2.start_session();
        document.getElementById("transcryptor_2_receiver_sks").value = response.key_share;
        document.getElementById("transcryptor_2_receiver_session_id").value = response.session_id;
        updateReceiverSessionKey();

    });
    document.getElementById("receiver_start_session_3").addEventListener('submit', async (event) => {
        event.preventDefault();
        let response = await receiver_transcryptor_3.start_session();
        document.getElementById("transcryptor_3_receiver_sks").value = response.key_share;
        document.getElementById("transcryptor_3_receiver_session_id").value = response.session_id;
        updateReceiverSessionKey();
    });

    function updateReceiverSessionKey() {
        let sks = [];
        try {
            sks.push(new SessionKeyShare(ScalarNonZero.fromHex(document.getElementById("transcryptor_1_receiver_sks").value)));
            sks.push(new SessionKeyShare(ScalarNonZero.fromHex(document.getElementById("transcryptor_2_receiver_sks").value)));
            sks.push(new SessionKeyShare(ScalarNonZero.fromHex(document.getElementById("transcryptor_3_receiver_sks").value)));
        } catch(err) {
            return
        }
        PEPReceiverClient = new PEPClient(BLINDING_SECRET_PEP, sks);
        document.getElementById("receiver_session_key").value = "Established";
    }

    document.getElementById("encrypt_pseudonym").addEventListener('submit', async (event) => {
        event.preventDefault();
        if (!PEPSenderClient) {
            return new Error("PEP client not found - Please start a session first");
        }
        let pseudonym = new Pseudonym(GroupElement.fromHex(document.getElementById("sender_pseudonym").value));
        let encrypted_pseudonym = PEPSenderClient.encryptPseudonym(pseudonym);
        document.getElementById("sender_encrypted_pseudonym").value = encrypted_pseudonym.value.toBase64();
    });
    document.getElementById("encrypt_datapoint").addEventListener('submit', async (event) => {
        event.preventDefault();
        if (!PEPSenderClient) {
            return new Error("PEP client not found - Please start a session first");
        }
        let datapoint = new DataPoint(GroupElement.fromHex(document.getElementById("sender_datapoint").value));
        let encrypted_datapoint = PEPSenderClient.encryptData(datapoint);
        document.getElementById("sender_encrypted_datapoint").value = encrypted_datapoint.value.toBase64();
    });

    document.getElementById("sender_random_pseudonym").onclick = (_) => {
        let random_group_element = GroupElement.random();
        document.getElementById("sender_pseudonym").value = random_group_element.toHex();
    }
    document.getElementById("sender_random_datapoint").onclick = (_) => {
        let random_group_element = GroupElement.random();
        document.getElementById("sender_datapoint").value = random_group_element.toHex();
    }



    document.getElementById("transcryptor").addEventListener('submit', async (event) => {
        event.preventDefault();
        document.getElementById("transcryptor_1_input").value = document.getElementById("sender_encrypted_pseudonym").value;

        let input1 = document.getElementById("transcryptor_1_input").value;

        let in1 = new EncryptedPseudonym(ElGamal.fromBase64(input1));
        let out1 = await sender_transcryptor_1.pseudonymize(in1, document.getElementById("context_from_1").value, document.getElementById("context_to_1").value, document.getElementById("session_from_1").value, document.getElementById("session_to_1").value);
        document.getElementById("transcryptor_output_1").value = out1;

        let in2 = new EncryptedPseudonym(ElGamal.fromBase64(out1));
        let out2 = await sender_transcryptor_2.pseudonymize(in2, document.getElementById("context_from_2").value, document.getElementById("context_to_2").value, document.getElementById("session_from_2").value, document.getElementById("session_to_2").value);
        document.getElementById("transcryptor_output_3").value = out2;

        let in3 = new EncryptedPseudonym(ElGamal.fromBase64(out2));
        let out3 = await sender_transcryptor_2.pseudonymize(in3, document.getElementById("context_from_3").value, document.getElementById("context_to_3").value, document.getElementById("session_from_3").value, document.getElementById("session_to_3").value);
        document.getElementById("transcryptor_output_3").value = out3;

        document.getElementById("receiver_encrypted_pseudonym").value = out3;
    });



    document.getElementById("decrypt_pseudonym").addEventListener('submit', async (event) => {
        event.preventDefault();
        if (!PEPReceiverClient) {
            return new Error("PEP client not found - Please start a session first");
        }
        let encrypted_pseudonym = new EncryptedDataPoint(GroupElement.fromBase64(document.getElementById("encrypted_pseudonym").value));
        let pseudonym = PEPReceiverClient.decryptPseudonym(encrypted_pseudonym);
        document.getElementById("decrypted_pseudonym").value = pseudonym.value.toHex();
    });

    document.getElementById("decrypt_datapoint").addEventListener('submit', async (event) => {
        event.preventDefault();
        if (!PEPReceiverClient) {
            return new Error("PEP client not found - Please start a session first");
        }
        let encrypted_datapoint = new EncryptedDataPoint(GroupElement.fromBase64(document.getElementById("encrypted_datapoint").value));
        let datapoint = PEPReceiverClient.decryptData(encrypted_datapoint);
        document.getElementById("decrypted_datapoint").value = datapoint.value.toHex();
    });

    function updateTranscryptorStatus() {
        sender_transcryptor_1.check_status();
        sender_transcryptor_2.check_status();
        sender_transcryptor_3.check_status();

        document.getElementById("transcryptor_1_status").value = sender_transcryptor_1.status.state + " @ " + (new Date(sender_transcryptor_1.status.last_checked)).toLocaleTimeString();
        document.getElementById("transcryptor_2_status").value = sender_transcryptor_2.status.state + " @ " + (new Date(sender_transcryptor_2.status.last_checked)).toLocaleTimeString();
        document.getElementById("transcryptor_3_status").value = sender_transcryptor_3.status.state + " @ " + (new Date(sender_transcryptor_3.status.last_checked)).toLocaleTimeString();
    }
    window.setInterval(updateTranscryptorStatus, 20000);
});