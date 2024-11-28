import { StartSessionResponse } from "./types";

export class PEPTranscryptorClient {
  private url: string;
  private auth_token: string;
  private status: { state: string; last_checked: number };
  private session_id: string | null;

  constructor(url: string, auth_token: string) {
    this.url = url;
    this.auth_token = auth_token;
    this.status = {
      state: "unknown",
      last_checked: Date.now(),
    };
    this.session_id = null;
  }

  async check_status() {
    let response = await fetch(this.url + "/status").catch((err) => {
      this.status = {
        state: "error",
        last_checked: Date.now(),
      };
      return err;
    });

    if (!response.ok) {
      this.status = {
        state: response.status === 404 ? "offline" : "error",
        last_checked: Date.now(),
      };
      return;
    } else {
      this.status = {
        state: "online",
        last_checked: Date.now(),
      };
    }
  }

  async start_session() {
    let response = await fetch(this.url + "/start_session", {
      method: "POST",
      mode: "cors",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer " + this.auth_token,
      },
    }).catch((err) => {
      this.status = {
        state: "error",
        last_checked: Date.now(),
      };
      return err;
    });

    if (response.ok) {
      let data: StartSessionResponse = await response.json();
      this.session_id = data.session_id;
      return data;
    }
  }

  async pseudonymize(
    encrypted_pseudonym,
    pseudonym_context_from,
    pseudonym_context_to,
    enc_context,
    dec_context,
  ) {
    let response = await fetch(this.url + "/pseudonymize", {
      method: "POST",
      mode: "cors",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer " + this.auth_token,
      },
      body: JSON.stringify({
        encrypted_pseudonym,
        pseudonym_context_from,
        pseudonym_context_to,
        enc_context,
        dec_context,
      }),
    }).catch((err) => {
      this.status = {
        state: "error",
        last_checked: Date.now(),
      };
      return err;
    });

    if (response.ok) {
      return await response.json();
    }
  }

  async get_sessions(username = null) {
    let response = await fetch(
      `${this.url}/get_sessions${username ? "/" + username : ""}`,
      {
        method: "GET",
        mode: "cors",
        headers: {
          "Content-Type": "application/json",
          Authorization: "Bearer " + this.auth_token,
        },
      },
    ).catch((err) => {
      this.status = {
        state: "error",
        last_checked: Date.now(),
      };
      return err;
    });

    if (response.ok) {
      return await response.json();
    }
  }
}
