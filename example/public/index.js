class transcriptor {

    constructor(url) {
        this.url = url;
        this.system_id = null;
        this.status = {
            state: 'unknown',
            last_checked: Date.now()
        };
    }

    async check_status() {
        let response = await fetch(this.url + '/status');
        let data = await response.json();
        if(response.status !== 200) {
            this.status = {
                state: response.status === 404 ? 'offline' : 'error',
                last_checked: Date.now()
            }
            return
        }
        this.status = {
            state: 'online',
            last_checked: Date.now()
        }
        this.system_id = data.system_id;
    }

    // TODO: Implement pseudonymize code etc.
}

// Transcriptor collection
const transcriptors = []

// Sync transcriptor status with the list
function update_transcriptor_list(){
    transcriptors.forEach(transcriptor => {
        transcriptor.check_status();
    });
    document.getElementById('transcriptor_list').innerHTML = transcriptors.map(transcriptor => {
        return `<li class="list-group-item">${transcriptor.system_id} - ${transcriptor.url} - ${transcriptor.status.state}</li>`
    }).join('');
}

// Run after HTML is loaded
document.addEventListener('DOMContentLoaded', () => {
    const transcriptor_form = document.getElementById('transcriptor_form');
    console.log(transcriptor_form);
    transcriptor_form.addEventListener('submit', async (event) => {
        event.preventDefault();
        const url = event.target.transcriptor_url.value;
        transcriptors.push(new transcriptor(url));
        update_transcriptor_list();
    });

});
