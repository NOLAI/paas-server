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

        // TODO: Because of CORS we don't get here...
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
            method: 'POST',
            mode: 'cors',
            headers: {
                'Content-Type': 'application/json',
                'Authorization': 'Bearer ' + auth_token
            },
            body: JSON.stringify({})
        }).catch(err => {
            this.status = {
                state: 'error', last_checked: Date.now()
            }
            return err;
        });

        if(response.ok){
            return await response.json();
        }
    }
}

// transcryptor collection
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

// Run after HTML is loaded
document.addEventListener('DOMContentLoaded', () => {
    const transcryptor_form = document.getElementById('start_session');

    transcryptor_form.addEventListener('submit', async (event) => {
        event.preventDefault();
        transcryptors = [];
        const urls = [event.target.transcryptor_1.value, event.target.transcryptor_2.value, event.target.transcryptor_3.value];
        console.log(urls);
        for (const url of urls) {
            if (url === '') continue;
            const new_transcryptor = new transcryptor(url);
            await new_transcryptor.check_status();
            transcryptors.push(new_transcryptor);
        }

        await update_transcryptor_list();

        const sessions = [];
        for (let i = 0; i < transcryptors.length; i++) {
            let transcryptor = transcryptors[i];
            let auth_token = event.target.auth_token.value;
            let session = await transcryptor.start_session(auth_token);
            sessions.push(session);
        }

        console.log(sessions);

    });

    window.setInterval(update_transcryptor_list, 60000);
});
