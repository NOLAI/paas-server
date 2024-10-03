import * as libpep from "./libpep.js";
import {
    BlindedGlobalSecretKey,
    DataPoint,
    ElGamal,
    EncryptedDataPoint,
    GroupElement,
    PEPClient,
    ScalarNonZero,
    SessionKeyShare
} from "./libpep.js";

document.addEventListener('DOMContentLoaded', async () => {
    await libpep.default();

    const BLINDING_SECRET = "22e81de441de01e689873e5b7a0c0166f295b75d4bd5b15ad1a5079c919dd007";
    const BLINDING_SECRET_PEP = new BlindedGlobalSecretKey(ScalarNonZero.fromHex(BLINDING_SECRET));

    let PEP_client = null;

    class transcryptor {

        constructor(url) {
            this.url = url;
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

        // TODO: Implement pseudonymize code etc.

        async start_session(auth_token) {
            let response = await fetch(this.url + '/start_session', {
                method: 'GET',
                mode: 'cors',
                headers: {
                    'Content-Type': 'application/json',
                    'Authorization': 'Bearer ' + auth_token
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
    }

    let transcryptors = []

    async function transcryptor_form_function(event) {
        try {
            transcryptors = [];
            const urls = [event.target.transcryptor_1.value, event.target.transcryptor_2.value, event.target.transcryptor_3.value];

            // Construct transcryptor classes
            for (const url of urls) {
                if (url === '') continue;
                const new_transcryptor = new transcryptor(url);
                await new_transcryptor.check_status();
                transcryptors.push(new_transcryptor);
            }

            // Update html
            await update_transcryptor_list();

            // Request sessions from transcryptors
            const sessions = [];
            for (let i = 0; i < transcryptors.length; i++) {
                let transcryptor = transcryptors[i];
                let auth_token = event.target.auth_token.value;
                let session = await transcryptor.start_session(auth_token);
                sessions.push(new SessionKeyShare(ScalarNonZero.fromHex(session.key_share)));
            }


            PEP_client = new PEPClient(BLINDING_SECRET_PEP, sessions);

            update_session_form(true);
        } catch (error) {
            console.log(error);
            update_session_form(false);
        }
    }

    async function encryption_form_function(event) {
        if (!PEP_client) {
            // TODO: throw error
            return;
        }

        let datapoint_plaintext = new DataPoint(GroupElement.fromHex(event.target.encrypt_plaintext.value));

        document.getElementById("encryption_result").innerText = PEP_client.encryptData(datapoint_plaintext).value.toBase64();
    }

    async function decryption_form_function(event) {
        if (!PEP_client) {
            // TODO: throw error
            return;
        }

        let encrypted_datapoint = new EncryptedDataPoint(ElGamal.fromBase64(event.target.decrypt_ciphertext.value));

        document.getElementById("decryption_result").innerText = PEP_client.decryptData(encrypted_datapoint).value.toHex();
    }

// Sync transcryptor status with the list
    function update_transcryptor_list() {
        transcryptors.forEach(transcryptor => {
            transcryptor.check_status();
        });
        for (let i = 0; i < transcryptors.length; i++) {
            let transcryptor = transcryptors[i];
            let transcryptor_input_row = document.getElementById(`transcryptor_${i + 1}_addon`);
            transcryptor_input_row.innerHTML =
                `Transcryptor ${i + 1} - <span class="${transcryptor.status.state === 'online' ? 'text-success' : 'text-danger'}">
             ${transcryptor.status.state} - Last checked on: ${(new Date(transcryptor.status.last_checked)).toLocaleTimeString()}</span>`;
        }
    }

// Show that the call succeeded
    function update_session_form(success) {
        let result_wrapper = document.getElementById('start_session_result');
        if (success) {
            result_wrapper.innerHTML = "<span class='badge text-bg-success mb-3'>Success</span>"
        } else {
            result_wrapper.innerHTML = "<span class='badge text-danger mb-3'>Error</span>"
        }
    }

// Run after HTML is loaded


    const transcryptor_form = document.getElementById('start_session');
    transcryptor_form.addEventListener('submit', async (event) => {
        event.preventDefault();
        await transcryptor_form_function(event);
    });

    const encryption_form = document.getElementById('encrypt');
    encryption_form.addEventListener('submit', async (event) => {
        event.preventDefault();
        await encryption_form_function(event);
    })

    const decryption_form = document.getElementById('decrypt');
    decryption_form.addEventListener('submit', async (event) => {
        event.preventDefault();
        await decryption_form_function(event);
    })


    document.getElementById("random_encryption").onclick = (_) => {
        if (!PEP_client) {
            // TODO: throw error
            return;
        }

        let random_group_element = GroupElement.random();

        let encryption_plaintext_textarea = document.getElementById("encrypt_plaintext");
        encryption_plaintext_textarea.value = random_group_element.toHex();
    }

    window.setInterval(update_transcryptor_list, 60000);
});