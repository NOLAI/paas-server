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
  SessionKeyShare,
} from "@nolai/libpep-wasm";

import type { StartSessionResponse } from "./types";

export class PEPTranscryptor {
  private url: string;
  private authToken: string;
  private status: { state: string; lastChecked: number };
  private sessionId: string | null;

  public constructor(url: string, authToken: string) {
    this.url = url;
    this.authToken = authToken;
    this.status = {
      state: "unknown",
      lastChecked: Date.now(),
    };
    this.sessionId = null;
  }

  public async checkStatus() {
    const response = await fetch(this.url + "/status").catch((err) => {
      this.status = {
        state: "error",
        lastChecked: Date.now(),
      };
      return err;
    });

    if (!response.ok) {
      this.status = {
        state: response.status === 404 ? "offline" : "error",
        lastChecked: Date.now(),
      };
    } else {
      this.status = {
        state: "online",
        lastChecked: Date.now(),
      };
    }
  }

  public async startSession() {
    const response = await fetch(this.url + "/start_session", {
      method: "POST",
      mode: "cors",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer " + this.authToken,
      },
    }).catch((err) => {
      this.status = {
        state: "error",
        lastChecked: Date.now(),
      };
      return err;
    });

    if (response.ok) {
      const data: StartSessionResponse = await response.json();
      this.sessionId = data.session_id;

      return {
        sessionId: data.session_id,
        keyShare: SessionKeyShare.fromHex(data.key_share),
      };
    } else {
      throw new Error(`Failed to start session with ${this.getUrl()}`);
    }
  }

  public async pseudonymize(
    encryptedPseudonym: EncryptedPseudonym,
    pseudonymContextFrom: string,
    pseudonymContextTo: string,
    encContext: string,
    decContext: string,
  ): Promise<EncryptedPseudonym> {
    const response = await fetch(this.url + "/pseudonymize", {
      method: "POST",
      mode: "cors",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer " + this.authToken,
      },
      body: JSON.stringify({
        // eslint-disable-next-line camelcase
        encrypted_pseudonym: encryptedPseudonym.toBase64(),
        // eslint-disable-next-line camelcase
        pseudonym_context_from: pseudonymContextFrom,
        // eslint-disable-next-line camelcase
        pseudonym_context_to: pseudonymContextTo,
        // eslint-disable-next-line camelcase
        enc_context: encContext,
        // eslint-disable-next-line camelcase
        dec_context: decContext,
      }),
    }).catch((err) => {
      this.status = {
        state: "error",
        lastChecked: Date.now(),
      };
      return err;
    });

    if (response.ok) {
      const data = await response.json();
      return EncryptedPseudonym.fromBase64(data.encrypted_pseudonym);
    }
  }

  public async getSessions(username = null) {
    const response = await fetch(
      `${this.url}/get_sessions${username ? "/" + username : ""}`,
      {
        method: "GET",
        mode: "cors",
        headers: {
          "Content-Type": "application/json",
          Authorization: "Bearer " + this.authToken,
        },
      },
    ).catch((err) => {
      this.status = {
        state: "error",
        lastChecked: Date.now(),
      };
      return err;
    });

    if (response.ok) {
      return await response.json();
    }
  }

  public getStatus() {
    return this.status;
  }

  public getSessionId() {
    return this.sessionId;
  }

  public getUrl() {
    return this.url;
  }
}

export interface PseudonymServiceConfig {
  blindedGlobalPrivateKey: string;
  globalPublicKey: string;
  transcryptors: PEPTranscryptor[];
}

export class PseudonymService {
  private config: PseudonymServiceConfig;
  private context: string;
  private global: boolean;
  private pepClient: PEPClient | null = null;

  public constructor(
    config: PseudonymServiceConfig,
    pseudonymContext: string,
    global = false,
  ) {
    this.config = config;
    this.context = pseudonymContext;
    this.global = global;
  }

  private getTranscryptorOrder(order: "random" | "default" | number[]) {
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
    if (this.global) {
      throw new Error("Global pseudonymization not supported yet");
      // this.pepClient = new OfflinePEPClient(
    } else {
      const sks = await Promise.all(
        this.config.transcryptors.map(
          async (instance) => (await instance.startSession()).keyShare,
        ),
      );
      this.pepClient = new PEPClient(
        new BlindedGlobalSecretKey(
          ScalarNonZero.fromHex(this.config.blindedGlobalPrivateKey),
        ),
        sks,
      );
    }
  }

  public async pseudonymize(
    encryptedPseudonym: string,
    pseudonymContextTo: string,
    encryptionContextFrom: string[], // TODO: Order should be the same as the transcryptors
    order?: "random" | number[], //TODO: I don't think default is the right word here
  ) {
    if (this.global) {
      throw new Error("Pseudonymization with global not supported yet");
    }

    // TODO: maybe check if pseudonym is base64 encoded
    let pseudonym = EncryptedPseudonym.fromBase64(encryptedPseudonym);

    if (!this.pepClient) {
      await this.createPEPClient();
    }

    order = this.getTranscryptorOrder(order);

    for (const i of order) {
      const transcryptor = this.config.transcryptors[i];
      pseudonym = await transcryptor.pseudonymize(
        pseudonym, //encrypted_pseudonym
        this.context, //pseudonym_context_from
        pseudonymContextTo, //pseudonym_context_to
        encryptionContextFrom[i], //enc_context
        transcryptor.getSessionId(), //dec_context
      );
    }

    return pseudonym;
  }

  public async pseudonymizeBatch() {} // TODO: Job vragen

  public async encryptPseudonym(pseudonym: string) {
    const pseudonymWASM = Pseudonym.fromHex(pseudonym);

    if (!this.pepClient) {
      await this.createPEPClient();
    }

    return this.pepClient.encryptPseudonym(pseudonymWASM);
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
}
