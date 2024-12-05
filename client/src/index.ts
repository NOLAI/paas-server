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
} from "@nolai/libpep-wasm";

import type { StartSessionResponse } from "./types";
// export interface StartSessionResponse {
//   session_id: string;
//   key_share: SessionKeyShare;
// }

export class PEPTranscryptor {
  private url: string;
  private auth_token: string;
  private status: { state: string; last_checked: number };
  private session_id: string | null;

  public constructor(url: string, auth_token: string) {
    this.url = url;
    this.auth_token = auth_token;
    this.status = {
      state: "unknown",
      last_checked: Date.now(),
    };
    this.session_id = null;
  }

  public async check_status() {
    const response = await fetch(this.url + "/status").catch((err) => {
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
    } else {
      this.status = {
        state: "online",
        last_checked: Date.now(),
      };
    }
  }

  public async start_session() {
    const response = await fetch(this.url + "/start_session", {
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
      const data: StartSessionResponse = await response.json();
      this.session_id = data.session_id;
      return data;
    } else {
      throw new Error(`Failed to start session with ${this.get_url()}`);
    }
  }

  public async pseudonymize(
    encrypted_pseudonym: EncryptedPseudonym,
    pseudonym_context_from: string,
    pseudonym_context_to: string,
    enc_context: string,
    dec_context: string,
  ): Promise<EncryptedPseudonym> {
    const response = await fetch(this.url + "/pseudonymize", {
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

  public async get_sessions(username = null) {
    const response = await fetch(
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

  public get_status() {
    return this.status;
  }

  public get_session_id() {
    return this.session_id;
  }

  public get_url() {
    return this.url;
  }
}

export interface PseudonymServiceConfig {
  blinded_global_private_key: string;
  transcryptors: PEPTranscryptor[];
}

export class PseudonymService {
  private config: PseudonymServiceConfig;
  private context: string;
  private global: boolean;
  private pepClient: PEPClient | null = null;

  public constructor(
    config: PseudonymServiceConfig,
    pseudonym_context: string,
    global = false,
  ) {
    this.config = config;
    this.context = pseudonym_context;
    this.global = global;
  }

  private get_transcryptor_order(order: "random" | "default" | number[]) {
    if (order === "default") {
      order = [...Array(this.config.transcryptors.length).keys()];
    } else if (order === "random" || !order) {
      order = [...Array(this.config.transcryptors.length).keys()].sort(
        () => Math.random() - 0.5,
      );
    }
    return order;
  }

  public async createPEPClient() {
    const sks = await Promise.all(
      this.config.transcryptors.map(
        async (instance) => (await instance.start_session()).key_share,
      ),
    );

    this.pepClient = new PEPClient(
      new BlindedGlobalSecretKey(
        ScalarNonZero.fromHex(this.config.blinded_global_private_key),
      ),
      sks,
    );
  }

  public async pseudonymize(
    encrypted_pseudonym: string,
    pseudonym_context_from: string,
    encryption_context_from: string,
    order?: "random" | "default" | number[], //TODO: I don't think default is the right word here
  ) {
    // TODO: maybe check if pseudonym is base64 encoded
    const pseudonym = new EncryptedPseudonym(
      ElGamal.fromBase64(encrypted_pseudonym),
    );

    if (!this.pepClient) {
      await this.createPEPClient();
    }

    order = this.get_transcryptor_order(order);

    let temp_response = pseudonym;
    for (const i of order) {
      const transcryptor = this.config.transcryptors[i];
      temp_response = await transcryptor.pseudonymize(
        temp_response, //encrypted_pseudonym
        pseudonym_context_from, //pseudonym_context_from
        this.context, //pseudonym_context_to
        encryption_context_from, //enc_context
        transcryptor.get_session_id(), //dec_context
      );
    }

    return temp_response;
  }

  public async pseudonymize_batch() {} // TODO: Job vragen

  public async encryptPseudonym(pseudonym: string) {
    const pseudonym_wasm = Pseudonym.fromHex(pseudonym);

    if (!this.pepClient) {
      await this.createPEPClient();
    }

    return this.pepClient.encryptPseudonym(pseudonym_wasm);
  }

  public async encryptData(data: string) {
    const datapoint = new DataPoint(GroupElement.fromHex(data));

    if (!this.pepClient) {
      await this.createPEPClient();
    }

    return this.pepClient.encryptData(datapoint);
  }

  public async decryptPseudonym(encryptedPseudonym: string) {
    const encryptedPseudonymWasm = new EncryptedPseudonym(
      ElGamal.fromBase64(encryptedPseudonym),
    );

    if (!this.pepClient) {
      await this.createPEPClient();
    }

    return this.pepClient.decryptPseudonym(encryptedPseudonymWasm);
  }

  public async decryptData(encryptedData: EncryptedDataPoint) {
    if (!this.pepClient) {
      await this.createPEPClient();
    }

    return this.pepClient.decryptData(encryptedData);
  }

  // public async rerandomizePseudonym(encryptedPseudonym: EncryptedPseudonym) {
  //   if (!this.pepClient) {
  //     await this.createPEPClient();
  //   }
  //   // TODO: Add to pepClient volgens mij
  // }
}
