import * as libpep from "./libpep.js";
import {BlindedGlobalSecretKey, PEPClient, ScalarNonZero, SessionKeyShare} from "./libpep.js";

const BLINDING_SECRET = "22e81de441de01e689873e5b7a0c0166f295b75d4bd5b15ad1a5079c919dd007"
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
function update_session_form(success){
    let result_wrapper = document.getElementById('start_session_result');
    if (success) {
        result_wrapper.innerHTML = "<span class='badge text-bg-success mb-3'>Success</span>"
    }else{
        result_wrapper.innerHTML = "<span class='badge text-danger mb-3'>Error</span>"
    }
}

// Run after HTML is loaded
document.addEventListener('DOMContentLoaded', async () => {
    await libpep.default();
    const BLINDING_SECRET_PEP = new BlindedGlobalSecretKey(ScalarNonZero.fromHex(BLINDING_SECRET));

    const transcryptor_form = document.getElementById('start_session');
    transcryptor_form.addEventListener('submit', async (event) => {
        event.preventDefault();

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
        }catch (error) {
            console.log(error);
            update_session_form(false);
        }
    });

    window.setInterval(update_transcryptor_list, 60000);
});