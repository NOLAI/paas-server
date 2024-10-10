import {
    BlindedGlobalSecretKey,
    BlindingFactor, DataPoint, ElGamal, EncryptedDataPoint,
    GlobalSecretKey, GroupElement,
    makeBlindedGlobalSecretKey,
    PEPClient,
    ScalarNonZero,
    SessionKeyShare
} from "./libpep.js";

import * as libpep from "./libpep.js";

document.addEventListener('DOMContentLoaded', async () => {
    try {
        await libpep.default();
    } catch (e) {
        console.error("Error in libpep", e);
    }


    const BLINDING_SECRET_PEP = new BlindedGlobalSecretKey(ScalarNonZero.fromHex("22e81de441de01e689873e5b7a0c0166f295b75d4bd5b15ad1a5079c919dd007"));

    let sender_pep_client = null;
    let receiver_pep_client = null;

    class transcryptor {

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

    let sender_transcryptors = []
    let receiver_transcryptors = []

    async function transcryptor_form_function(event, sender=true) {
        const prefix = sender ? "sender" : "receiver";

        const update_session_form = (success) => {
            let result_wrapper = document.getElementById(`${prefix}_start_session_result`);
            if (success) {
                result_wrapper.innerHTML = "<span class='badge text-bg-success'>Success</span>"
            } else {
                result_wrapper.innerHTML = "<span class='badge text-danger'>Error</span>"
            }
        }

        try {
            let selected_transcryptors = [];

            const urls = [event.target[`${prefix}_transcryptor_1`].value, event.target[`${prefix}_transcryptor_2`].value, event.target[`${prefix}_transcryptor_3`].value];
            let auth_token = event.target[`${prefix}_auth_token`].value;

            // Construct transcryptor classes
            for (const url of urls) {
                if (url === '') continue;
                const new_transcryptor = new transcryptor(url, auth_token);
                await new_transcryptor.check_status();
                selected_transcryptors.push(new_transcryptor);
            }

            // Update html
            await update_transcryptor_list(sender);

            // Request sessions from transcryptors
            const sessions = [];
            for (let i = 0; i < selected_transcryptors.length; i++) {
                let transcryptor = selected_transcryptors[i];
                let session = await transcryptor.start_session();

                update_transcryptor_session(i + 1, session.session_id, sender);

                sessions.push(new SessionKeyShare(ScalarNonZero.fromHex(session.key_share)));
            }

            if (sender) {
                sender_transcryptors = selected_transcryptors;
                sender_pep_client = new PEPClient(BLINDING_SECRET_PEP, sessions);
            }else{
                receiver_transcryptors = selected_transcryptors;
                receiver_pep_client = new PEPClient(BLINDING_SECRET_PEP, sessions);
            }

            update_session_form(true);


            update_sessions(sender, 0, 1);
            update_sessions(sender, 1, 2);
            update_sessions(sender, 2, 3);


        } catch (error) {
            console.log(error);
            update_session_form(false);
        }
    }

    async function encryption_form_function(event) {
        if (!sender_pep_client) {
            return new Error("PEP client not found - Please start a session first");
        }

        let datapoint_plaintext = new DataPoint(GroupElement.fromHex(event.target.encrypt_pseudonym.value));

        document.getElementById("encryption_result").innerText = sender_pep_client.encryptData(datapoint_plaintext).value.toBase64();
    }

    async function pseudonymize_form_function(event) {

        if (!receiver_pep_client){
            return new Error("PEP client not found - Please start a session first");
        }

        let encrypted_pseudonym = event.target.pseudonymize_input.value;

        // First transcryptor
        let first_transcryptor = receiver_transcryptors[event.target.pseudonymize_transcryptor_order_1.value];
        let pseudonym_context_from = event.target.pseudonymize_transcryptor_1_context_from.value;
        let pseudonym_context_to = event.target.pseudonymize_transcryptor_1_context_to.value;
        let enc_context = event.target.pseudonymize_transcryptor_1_encryption.value;
        let dec_context = event.target.pseudonymize_transcryptor_1_decryption.value;

        let first_result = await first_transcryptor.pseudonymize(encrypted_pseudonym, pseudonym_context_from, pseudonym_context_to, enc_context, dec_context);
        update_transcryptor_result(1, first_result.encrypted_pseudonym);

        // Second transcryptor
        let second_transcryptor = receiver_transcryptors[event.target.pseudonymize_transcryptor_order_2.value];
        pseudonym_context_from = event.target.pseudonymize_transcryptor_2_context_from.value;
        pseudonym_context_to = event.target.pseudonymize_transcryptor_2_context_to.value;
        enc_context = event.target.pseudonymize_transcryptor_2_encryption.value;
        dec_context = event.target.pseudonymize_transcryptor_2_decryption.value;

        let second_result = await second_transcryptor.pseudonymize(first_result.encrypted_pseudonym, pseudonym_context_from, pseudonym_context_to, enc_context, dec_context);
        update_transcryptor_result(2, second_result.encrypted_pseudonym);

        // Third transcryptor
        let third_transcryptor = receiver_transcryptors[event.target.pseudonymize_transcryptor_order_3.value];
        pseudonym_context_from = event.target.pseudonymize_transcryptor_3_context_from.value;
        pseudonym_context_to = event.target.pseudonymize_transcryptor_3_context_to.value;
        enc_context = event.target.pseudonymize_transcryptor_3_encryption.value;
        dec_context = event.target.pseudonymize_transcryptor_3_decryption.value;

        let third_result = await third_transcryptor.pseudonymize(second_result.encrypted_pseudonym, pseudonym_context_from, pseudonym_context_to, enc_context, dec_context);
        update_transcryptor_result(3, third_result.encrypted_pseudonym);

    }

    async function decryption_form_function(event) {
        if (!receiver_pep_client) {
            return new Error("PEP client not found - Please start a session first");
        }

        let encrypted_datapoint = new EncryptedDataPoint(ElGamal.fromBase64(event.target.decrypt_ciphertext.value));

        document.getElementById("decryption_result").innerText = receiver_pep_client.decryptData(encrypted_datapoint).value.toHex();
    }

// Sync transcryptor status with the list
    function update_transcryptor_list(sender=true) {
        let selected_transcryptor = sender ? sender_transcryptors : receiver_transcryptors;

        selected_transcryptor.forEach(transcryptor => {
            transcryptor.check_status();
        });
        for (let i = 0; i < selected_transcryptor.length; i++) {
            let transcryptor = selected_transcryptor[i];
            let transcryptor_input_row = document.getElementById(`${sender ? "sender" : "receiver"}_transcryptor_${i + 1}_addon`);

            transcryptor_input_row.innerHTML =
                `Transcryptor ${i + 1} - <span class="${transcryptor.status.state === 'online' ? 'text-success' : 'text-danger'}">
             ${transcryptor.status.state} - Last checked on: ${(new Date(transcryptor.status.last_checked)).toLocaleTimeString()}</span>`;
        }
    }

    function add_sessions_to_select(sessions, select_element, selected_session = null) {
        select_element.innerHTML = "";
        for (let session of sessions) {
            let option = document.createElement("option");
            option.value = session;
            option.text = session;
            if (selected_session && selected_session === session) {
                option.selected = true;
            }
            select_element.add(option);
        }
    }

    async function update_sessions(sender, transcryptor_index, select_index) {
        let selected_transcryptor = sender ? sender_transcryptors[transcryptor_index] : receiver_transcryptors[transcryptor_index];
        let selected_sessions = await selected_transcryptor.get_sessions();

        let form_select_element = document.getElementById(`pseudonymize_transcryptor_${select_index}_${sender ? "encryption" : "decryption"}`);

        add_sessions_to_select(selected_sessions.sessions, form_select_element, selected_transcryptor.session_id);
    }

    function update_transcryptor_result(index, result){
        document.getElementById(`pseudonymize_transcryptor_${index}_result`).innerText = result;
    }

    function update_transcryptor_session(index, session, sender) {
        document.getElementById(`${sender ? "sender" : "receiver"}_transcryptor_${index}_session_result`).innerText = session;
    }

// Run after HTML is loaded
    const sender_transcryptor_form = document.getElementById('sender_start_session');
    sender_transcryptor_form.addEventListener('submit', async (event) => {
        event.preventDefault();
        await transcryptor_form_function(event, true);
    });

    const receiver_transcryptor_form = document.getElementById('receiver_start_session');
    receiver_transcryptor_form.addEventListener('submit', async (event) => {
        event.preventDefault();
        await transcryptor_form_function(event, false);
    });

    const encryption_form = document.getElementById('encrypt');
    encryption_form.addEventListener('submit', async (event) => {
        event.preventDefault();
        await encryption_form_function(event);
    })

    const pseudonymize_form = document.getElementById('pseudonymize');
    pseudonymize_form.addEventListener('submit', async (event) => {
        event.preventDefault();
        await pseudonymize_form_function(event);
    })

    const decryption_form = document.getElementById('decrypt');
    decryption_form.addEventListener('submit', async (event) => {
        event.preventDefault();
        await decryption_form_function(event);
    })

    for(let i = 1; i <= 3; i++){
        document.getElementById(`pseudonymize_transcryptor_order_${i}`).onchange = (event) => {
            update_transcryptor_list(true);

            if(sender_pep_client){
                update_sessions(true, event.target.value, i);
            }

            if(receiver_pep_client) {
                update_sessions(false, event.target.value, i);
            }
        }

    }

    document.getElementById("random_encryption").onclick = (_) => {
        if (!sender_pep_client) {
            // TODO: throw error
            return;
        }

        let random_group_element = GroupElement.random();

        let encryption_plaintext_textarea = document.getElementById("encrypt_pseudonym");
        encryption_plaintext_textarea.value = random_group_element.toHex();
    }

    window.setInterval(() => {
        update_transcryptor_list(true);
        update_transcryptor_list(false);
    }, 60000);
});