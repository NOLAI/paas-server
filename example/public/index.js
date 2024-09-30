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
        let response = await fetch(this.url + '/status').catch(
            err => {
                this.status = {
                    state: 'error',
                    last_checked: Date.now()
                }
                return err;
            }
        );

        // TODO: Because of CORS we don't get here...
        if (!response.ok) {
            this.status = {
                state: response.status === 404 ? 'offline' : 'error',
                last_checked: Date.now()
            }
            return
        }
        let data = await response.json();
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
        let row  = `<li class="list-group-item">${transcriptor.system_id} - ${transcriptor.url}`
        row += ` - <span class="${transcriptor.status.state === 'online' ? 'text-success' : 'text-danger'}">${transcriptor.status.state}</span>`
        row += '</li>';
        return row;
    }).join('');
}

// Run after HTML is loaded
document.addEventListener('DOMContentLoaded', () => {
    const transcriptor_form = document.getElementById('transcriptor_form');

    transcriptor_form.addEventListener('submit', async (event) => {
        event.preventDefault();
        const url = event.target.transcriptor_url.value;

        const new_transcriptor = new transcriptor(url);
        await new_transcriptor.check_status();
        transcriptors.push(new_transcriptor);
        event.target.transcriptor_url.value = '';

        update_transcriptor_list();
    });

    window.setInterval(update_transcriptor_list, 60000);
});
