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
            this.session_id = null;
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
                let data = await response.json();
                this.session_id = data.session_id;
                return data;
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
        invalidateSender();
        await updateTranscryptorSessions();
    });
    document.getElementById("sender_start_session_2").addEventListener('submit', async (event) => {
        event.preventDefault();
        let response = await sender_transcryptor_2.start_session();
        document.getElementById("transcryptor_2_sender_sks").value = response.key_share;
        document.getElementById("transcryptor_2_sender_session_id").value = response.session_id;
        updateSenderSessionKey();
        invalidateSender();
        await updateTranscryptorSessions();
    });
    document.getElementById("sender_start_session_3").addEventListener('submit', async (event) => {
        event.preventDefault();
        let response = await sender_transcryptor_3.start_session();
        document.getElementById("transcryptor_3_sender_sks").value = response.key_share;
        document.getElementById("transcryptor_3_sender_session_id").value = response.session_id;
        updateSenderSessionKey();
        invalidateSender();
        await updateTranscryptorSessions();
    });

    function updateSenderSessionKey() {
        let sks = [];

        try {
            sks.push(new SessionKeyShare(ScalarNonZero.fromHex(document.getElementById("transcryptor_1_sender_sks").value)));
            sks.push(new SessionKeyShare(ScalarNonZero.fromHex(document.getElementById("transcryptor_2_sender_sks").value)));
            sks.push(new SessionKeyShare(ScalarNonZero.fromHex(document.getElementById("transcryptor_3_sender_sks").value)));
        } catch(err) {
            document.getElementById("sender_pseudonym_encrypt_button").disabled = true;
            document.getElementById("sender_datapoint_encrypt_button").disabled = true;
            return
        }

        PEPSenderClient = new PEPClient(BLINDING_SECRET_PEP, sks);
        document.getElementById("sender_pseudonym_encrypt_button").disabled = false;
        document.getElementById("sender_datapoint_encrypt_button").disabled = false;
        document.getElementById("sender_session_key").value = "Established";
    }

    document.getElementById("receiver_start_session_1").addEventListener('submit', async (event) => {
        event.preventDefault();
        let response = await receiver_transcryptor_1.start_session();
        document.getElementById("transcryptor_1_receiver_sks").value = response.key_share;
        document.getElementById("transcryptor_1_receiver_session_id").value = response.session_id;
        updateReceiverSessionKey();
        invalidateReceiver1();
        await updateTranscryptorSessions();
    });
    document.getElementById("receiver_start_session_2").addEventListener('submit', async (event) => {
        event.preventDefault();
        let response = await receiver_transcryptor_2.start_session();
        document.getElementById("transcryptor_2_receiver_sks").value = response.key_share;
        document.getElementById("transcryptor_2_receiver_session_id").value = response.session_id;
        updateReceiverSessionKey();
        invalidateReceiver2();
        await updateTranscryptorSessions();
    });
    document.getElementById("receiver_start_session_3").addEventListener('submit', async (event) => {
        event.preventDefault();
        let response = await receiver_transcryptor_3.start_session();
        document.getElementById("transcryptor_3_receiver_sks").value = response.key_share;
        document.getElementById("transcryptor_3_receiver_session_id").value = response.session_id;
        updateReceiverSessionKey();
        invalidateReceiver3();
        await updateTranscryptorSessions();
    });


    function updateReceiverSessionKey() {
        let sks = [];
        try {
            sks.push(new SessionKeyShare(ScalarNonZero.fromHex(document.getElementById("transcryptor_1_receiver_sks").value)));
            sks.push(new SessionKeyShare(ScalarNonZero.fromHex(document.getElementById("transcryptor_2_receiver_sks").value)));
            sks.push(new SessionKeyShare(ScalarNonZero.fromHex(document.getElementById("transcryptor_3_receiver_sks").value)));
        } catch(err) {
            document.getElementById("receiver_pseudonym_decrypt_button").disabled = true;
            document.getElementById("receiver_datapoint_decrypt_button").disabled = true;
            return
        }
        PEPReceiverClient = new PEPClient(BLINDING_SECRET_PEP, sks);
        document.getElementById("receiver_pseudonym_decrypt_button").disabled = false;
        document.getElementById("receiver_datapoint_decrypt_button").disabled = false;
        document.getElementById("receiver_session_key").value = "Established";
    }

    function add_sessions_to_select(sessions, select_element, selected_session = null) {
        select_element.innerHTML = "";

        let empty = document.createElement("option");
        empty.value = "0";
        empty.text = "Select...";
        empty.selected = true;
        empty.disabled = true;
        select_element.add(empty);

        for (let session of sessions) {
            let option = document.createElement("option");
            option.value = session;
            option.text = session;
            if (selected_session && selected_session === session) {
                empty.selected = false;
                option.selected = true;
            }
            select_element.add(option);
        }
    }

    function getFirstSenderTranscryptor() {
        if (document.getElementById("transcryptor_1").value === "0") {
            return sender_transcryptor_1;
        } else if (document.getElementById("transcryptor_1").value === "1") {
            return sender_transcryptor_2;
        } else if (document.getElementById("transcryptor_1").value === "2") {
            return sender_transcryptor_3;
        }
    }

    function getSecondSenderTranscryptor() {
        if (document.getElementById("transcryptor_2").value === "0") {
            return sender_transcryptor_1;
        } else if (document.getElementById("transcryptor_2").value === "1") {
            return sender_transcryptor_2;
        } else if (document.getElementById("transcryptor_2").value === "2") {
            return sender_transcryptor_3;
        }
    }

    function getThirdSenderTranscryptor() {
        if (document.getElementById("transcryptor_3").value === "0") {
            return sender_transcryptor_1;
        } else if (document.getElementById("transcryptor_3").value === "1") {
            return sender_transcryptor_2;
        } else if (document.getElementById("transcryptor_3").value === "2") {
            return sender_transcryptor_3;
        }
    }

    function getFirstReceiverTranscryptor() {
        if (document.getElementById("transcryptor_1").value === "0") {
            return receiver_transcryptor_1;
        } else if (document.getElementById("transcryptor_1").value === "1") {
            return receiver_transcryptor_2;
        } else if (document.getElementById("transcryptor_1").value === "2") {
            return receiver_transcryptor_3;
        }
    }

    function getSecondReceiverTranscryptor() {
        if (document.getElementById("transcryptor_2").value === "0") {
            return receiver_transcryptor_1;
        } else if (document.getElementById("transcryptor_2").value === "1") {
            return receiver_transcryptor_2;
        } else if (document.getElementById("transcryptor_2").value === "2") {
            return receiver_transcryptor_3;
        }
    }

    function getThirdReceiverTranscryptor() {
        if (document.getElementById("transcryptor_3").value === "0") {
            return receiver_transcryptor_1;
        } else if (document.getElementById("transcryptor_3").value === "1") {
            return receiver_transcryptor_2;
        } else if (document.getElementById("transcryptor_3").value === "2") {
            return receiver_transcryptor_3;
        }
    }

    async function updateTranscryptorSessions() {
        let firstTranscryptorSessions = await getFirstReceiverTranscryptor().get_sessions();
        add_sessions_to_select(firstTranscryptorSessions["sessions"].sort(),document.getElementById("session_from_1"), getFirstSenderTranscryptor().session_id)
        add_sessions_to_select(firstTranscryptorSessions["sessions"].sort(),document.getElementById("session_to_1"), getFirstReceiverTranscryptor().session_id)

        let secondTranscryptorSessions = await getSecondReceiverTranscryptor().get_sessions();
        add_sessions_to_select(secondTranscryptorSessions["sessions"].sort(),document.getElementById("session_from_2"), getSecondSenderTranscryptor().session_id)
        add_sessions_to_select(secondTranscryptorSessions["sessions"].sort(),document.getElementById("session_to_2"), getSecondReceiverTranscryptor().session_id)


        let thirdTranscryptorSessions = await getThirdReceiverTranscryptor().get_sessions();
        add_sessions_to_select(thirdTranscryptorSessions["sessions"].sort(),document.getElementById("session_from_3"), getThirdSenderTranscryptor().session_id)
        add_sessions_to_select(thirdTranscryptorSessions["sessions"].sort(),document.getElementById("session_to_3"), getThirdReceiverTranscryptor().session_id)

        let enabled = document.getElementById("session_from_1").value !== "0" && document.getElementById("session_from_2").value !== "0" && document.getElementById("session_from_3").value !== "0" && document.getElementById("session_to_1").value !== "0" && document.getElementById("session_to_2").value !== "0" && document.getElementById("session_to_3") !== "0";
        document.getElementById("pseudonymize_button").disabled = !enabled;
        document.getElementById("rekey_button").disabled = !enabled;
    }

    document.getElementById("encrypt_pseudonym").addEventListener('submit', async (event) => {
        event.preventDefault();
        if (!PEPSenderClient) {
            return new Error("PEP client not found - Please start a session first");
        }
        let pseudonym = new Pseudonym(GroupElement.fromHex(document.getElementById("sender_pseudonym").value));
        let encrypted_pseudonym = PEPSenderClient.encryptPseudonym(pseudonym);
        document.getElementById("sender_encrypted_pseudonym").value = encrypted_pseudonym.value.toBase64();
        document.getElementById("transcryptor_1_input").value = encrypted_pseudonym.value.toBase64();
        invalidateTranscryption1();
    });
    document.getElementById("encrypt_datapoint").addEventListener('submit', async (event) => {
        event.preventDefault();
        if (!PEPSenderClient) {
            return new Error("PEP client not found - Please start a session first");
        }
        let datapoint = new DataPoint(GroupElement.fromHex(document.getElementById("sender_datapoint").value));
        let encrypted_datapoint = PEPSenderClient.encryptData(datapoint);
        document.getElementById("sender_encrypted_datapoint").value = encrypted_datapoint.value.toBase64();
        document.getElementById("transcryptor_1_input").value = encrypted_datapoint.value.toBase64();
        invalidateTranscryption1();
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

        let input1 = document.getElementById("transcryptor_1_input").value;
        let in1 = new EncryptedPseudonym(ElGamal.fromBase64(input1));
        let out1 = await getFirstReceiverTranscryptor().pseudonymize(in1.value.toBase64(), document.getElementById("context_from_1").value, document.getElementById("context_to_1").value, document.getElementById("session_from_1").value, document.getElementById("session_to_1").value);
        document.getElementById("transcryptor_1_output").value = out1["encrypted_pseudonym"];
        document.getElementById("transcryptor_2_input").value = out1["encrypted_pseudonym"];

        let in2 = new EncryptedPseudonym(ElGamal.fromBase64(out1["encrypted_pseudonym"]));
        let out2 = await getSecondReceiverTranscryptor().pseudonymize(in2.value.toBase64(), document.getElementById("context_from_2").value, document.getElementById("context_to_2").value, document.getElementById("session_from_2").value, document.getElementById("session_to_2").value);
        document.getElementById("transcryptor_2_output").value = out2["encrypted_pseudonym"];
        document.getElementById("transcryptor_3_input").value = out2["encrypted_pseudonym"];

        let in3 = new EncryptedPseudonym(ElGamal.fromBase64(out2["encrypted_pseudonym"]));
        let out3 = await getThirdReceiverTranscryptor().pseudonymize(in3.value.toBase64(), document.getElementById("context_from_3").value, document.getElementById("context_to_3").value, document.getElementById("session_from_3").value, document.getElementById("session_to_3").value);
        document.getElementById("transcryptor_3_output").value = out3["encrypted_pseudonym"];
        document.getElementById("receiver_encrypted_pseudonym").value = out3["encrypted_pseudonym"];
    });

    document.getElementById("decrypt_pseudonym").addEventListener('submit', async (event) => {
        event.preventDefault();
        if (!PEPReceiverClient) {
            return new Error("PEP client not found - Please start a session first");
        }
        let encrypted_pseudonym = new EncryptedPseudonym(ElGamal.fromBase64(document.getElementById("receiver_encrypted_pseudonym").value));
        let pseudonym = PEPReceiverClient.decryptPseudonym(encrypted_pseudonym);
        document.getElementById("receiver_pseudonym_plaintext").value = pseudonym.value.toHex();
    });

    document.getElementById("decrypt_datapoint").addEventListener('submit', async (event) => {
        event.preventDefault();
        if (!PEPReceiverClient) {
            return new Error("PEP client not found - Please start a session first");
        }
        let encrypted_datapoint = new EncryptedDataPoint(ElGamal.fromBase64(document.getElementById("receiver_encrypted_datapoint").value));
        let datapoint = PEPReceiverClient.decryptData(encrypted_datapoint);
        document.getElementById("receiver_datapoint_plaintext").value = datapoint.value.toHex();
    });



    function invalidateTranscryption3() {
        document.getElementById("transcryptor_3_output").value = "";
        document.getElementById("receiver_encrypted_pseudonym").value = "";
        document.getElementById("receiver_encrypted_datapoint").value = "";
    }
    function invalidateTranscryption2() {
        document.getElementById("transcryptor_2_output").value = "";
        document.getElementById("transcryptor_3_input").value = "";
        invalidateTranscryption3()
    }
    function invalidateTranscryption1() {
        document.getElementById("transcryptor_1_output").value = "";
        document.getElementById("transcryptor_2_input").value = "";
        invalidateTranscryption2()
    }

    function invalidateSender() {
        document.getElementById("sender_encrypted_pseudonym").value = "";
        document.getElementById("sender_encrypted_datapoint").value = "";
        document.getElementById("transcryptor_1_input").value = "";
        invalidateTranscryption1();
        invalidateReceiver();
    }
    function invalidateReceiver() {
        invalidateTranscryption1();
    }


    function invalidateReceiver1() {
        if (getFirstReceiverTranscryptor() === receiver_transcryptor_1) {
            invalidateTranscryption1();
        } else if (getSecondReceiverTranscryptor() === receiver_transcryptor_1) {
            invalidateTranscryption2()
        } else if (getThirdReceiverTranscryptor() === receiver_transcryptor_1) {
            invalidateTranscryption3();
        }
    }
    function invalidateReceiver2() {
        if (getFirstReceiverTranscryptor() === receiver_transcryptor_2) {
            invalidateTranscryption1();
        } else if (getSecondReceiverTranscryptor() === receiver_transcryptor_2) {
            invalidateTranscryption2()
        } else if (getThirdReceiverTranscryptor() === receiver_transcryptor_2) {
            invalidateTranscryption3();
        }
    }

    function invalidateReceiver3() {
        if (getFirstReceiverTranscryptor() === receiver_transcryptor_3) {
            invalidateTranscryption1();
        } else if (getSecondReceiverTranscryptor() === receiver_transcryptor_3) {
            invalidateTranscryption2()
        } else if (getThirdReceiverTranscryptor() === receiver_transcryptor_3) {
            invalidateTranscryption3();
        }
    }



    document.getElementById("context_from_1").addEventListener("change", async (event) => {
        invalidateTranscryption1();
    })
    document.getElementById("context_from_2").addEventListener("change", async (event) => {
        invalidateTranscryption2();
    })
    document.getElementById("context_from_3").addEventListener("change", async (event) => {
        invalidateTranscryption3();
    })
    document.getElementById("context_to_1").addEventListener("change", async (event) => {
        invalidateTranscryption1();
    })
    document.getElementById("context_to_2").addEventListener("change", async (event) => {
        invalidateTranscryption2();
    })
    document.getElementById("context_to_3").addEventListener("change", async (event) => {
        invalidateTranscryption3();
    })
    document.getElementById("session_from_1").addEventListener("change", async (event) => {
        invalidateTranscryption1();
    })
    document.getElementById("session_from_2").addEventListener("change", async (event) => {
        invalidateTranscryption2();
    })
    document.getElementById("session_from_3").addEventListener("change", async (event) => {
        invalidateTranscryption3();
    })
    document.getElementById("session_to_1").addEventListener("change", async (event) => {
        invalidateTranscryption1();
    })
    document.getElementById("session_to_2").addEventListener("change", async (event) => {
        invalidateTranscryption2();
    })
    document.getElementById("session_to_3").addEventListener("change", async (event) => {
        invalidateTranscryption3();
    })
    document.getElementById("transcryptor_1").addEventListener("change", async (event) => {
        invalidateTranscryption1();
        await updateTranscryptorSessions();
    })
    document.getElementById("transcryptor_2").addEventListener("change", async (event) => {
        invalidateTranscryption2();
        await updateTranscryptorSessions();
    })
    document.getElementById("transcryptor_3").addEventListener("change", async (event) => {
        invalidateTranscryption3();
        await updateTranscryptorSessions();
    })

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