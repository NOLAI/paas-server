import {
  BlindedGlobalSecretKey,
  DataPoint,
  EncryptedDataPoint,
  EncryptedPseudonym,
  GlobalPublicKey,
  PEPClient,
  Pseudonym,
  SessionKeyShare,
} from "@nolai/libpep-wasm";

export interface StatusResponse {
  timestamp: string;
  system_id: string;
}

export interface StartSessionResponse {
  session_id: string;
  key_share: string;
}

export interface GetSessionResponse {
  sessions: string[];
}

export interface PseudonymizationResponse {
  encrypted_pseudonym: string;
}

export interface PseudonymizationRequest {
  encrypted_pseudonym: string;
  pseudonym_context_from: string;
  pseudonym_context_to: string;
  enc_context: string;
  dec_context: string;
}

export interface PseudonymizationBatchRequest {
  encrypted_pseudonyms: string[];
  pseudonym_context_from: string;
  pseudonym_context_to: string;
  enc_context: string;
  dec_context: string;
}

export interface PseudonymizationBatchResponse {
  encrypted_pseudonyms: string[];
}

export class PEPTranscryptor {
  private url: string;
  private jwt: string;
  private status: { state: string; lastChecked: number };
  private sessionId: string | null;
  private systemId: string | null;

  public constructor(url: string, jwt: string) {
    this.url = url;
    this.jwt = jwt;
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
      const data: StatusResponse = await response.json();
      this.systemId = data.system_id;
    }
  }

  public async startSession() {
    const response = await fetch(this.url + "/sessions/start", {
      method: "POST",
      mode: "cors",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer " + this.jwt,
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
        Authorization: "Bearer " + this.jwt,
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
      } as PseudonymizationRequest),
    }).catch((err) => {
      this.status = {
        state: "error",
        lastChecked: Date.now(),
      };
      return err;
    });

    if (response.ok) {
      const data: PseudonymizationResponse = await response.json();
      return EncryptedPseudonym.fromBase64(data.encrypted_pseudonym);
    }
  }

  public async pseudonymizeBatch(
    encryptedPseudonym: EncryptedPseudonym[],
    pseudonymContextFrom: string,
    pseudonymContextTo: string,
    encContext: string,
    decContext: string,
  ): Promise<EncryptedPseudonym[]> {
    const response = await fetch(this.url + "/pseudonymize_batch", {
      method: "POST",
      mode: "cors",
      headers: {
        "Content-Type": "application/json",
        Authorization: "Bearer " + this.jwt,
      },
      body: JSON.stringify({
        // eslint-disable-next-line camelcase
        encrypted_pseudonyms: encryptedPseudonym.map((p) => p.toBase64()),
        // eslint-disable-next-line camelcase
        pseudonym_context_from: pseudonymContextFrom,
        // eslint-disable-next-line camelcase
        pseudonym_context_to: pseudonymContextTo,
        // eslint-disable-next-line camelcase
        enc_context: encContext,
        // eslint-disable-next-line camelcase
        dec_context: decContext,
      } as PseudonymizationBatchRequest),
    }).catch((err) => {
      this.status = {
        state: "error",
        lastChecked: Date.now(),
      };
      return err;
    });

    if (response.ok) {
      const data: PseudonymizationBatchResponse = await response.json();
      return data.encrypted_pseudonyms.map((p) =>
        EncryptedPseudonym.fromBase64(p),
      );
    }
  }

  public async getSessions(username = null) {
    const response = await fetch(
      `${this.url}/sessions/get${username ? "/" + username : ""}`,
      {
        method: "GET",
        mode: "cors",
        headers: {
          "Content-Type": "application/json",
          Authorization: "Bearer " + this.jwt,
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
      const data: GetSessionResponse = response.json();
      return data.sessions;
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

  public getSystemId() {
    return this.systemId;
  }
}

export interface PseudonymServiceConfig {
  blindedGlobalPrivateKey: BlindedGlobalSecretKey;
  globalPublicKey: GlobalPublicKey;
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
      await Promise.all(
        this.config.transcryptors.map(
          async (instance) => await instance.checkStatus(),
        ),
      );

      for (const transcryptor of this.config.transcryptors) {
        if (transcryptor.getStatus().state !== "online") {
          throw new Error(
            `Transcryptor ${transcryptor.getUrl()} is not online`,
          );
        }
      }

      const sks = await Promise.all(
        this.config.transcryptors.map(
          async (instance) => (await instance.startSession()).keyShare,
        ),
      );
      this.pepClient = new PEPClient(this.config.blindedGlobalPrivateKey, sks);
    }
  }

  public async pseudonymize(
    encryptedPseudonym: EncryptedPseudonym,
    pseudonymContextTo: string,
    encryptionContextFrom: string[], // TODO: Order should be the same as the transcryptors
    order?: "random" | number[], //TODO: I don't think default is the right word here
  ) {
    if (this.global) {
      throw new Error("Pseudonymization with global not supported yet");
    }

    if (!this.pepClient) {
      await this.createPEPClient();
    }

    order = this.getTranscryptorOrder(order);

    for (const i of order) {
      const transcryptor = this.config.transcryptors[i];
      encryptedPseudonym = await transcryptor.pseudonymize(
        encryptedPseudonym, //encrypted_pseudonym
        this.context, //pseudonym_context_from
        pseudonymContextTo, //pseudonym_context_to
        encryptionContextFrom[i], //enc_context
        transcryptor.getSessionId(), //dec_context
      );
      // TODO: Handle error if pseudonymization fails
    }

    return encryptedPseudonym;
  }

  public async pseudonymizeBatch(
    encryptedPseudonyms: EncryptedPseudonym[],
    pseudonymContextTo: string,
    encryptionContextFrom: string[], // TODO: Order should be the same as the transcryptors
    order?: "random" | number[],
  ) {
    if (this.global) {
      throw new Error("Pseudonymization with global not supported yet");
    }

    if (!this.pepClient) {
      await this.createPEPClient();
    }

    order = this.getTranscryptorOrder(order);

    for (const i of order) {
      const transcryptor = this.config.transcryptors[i];
      encryptedPseudonyms = await transcryptor.pseudonymizeBatch(
        encryptedPseudonyms, //encrypted_pseudonym[]
        this.context, //pseudonym_context_from
        pseudonymContextTo, //pseudonym_context_to
        encryptionContextFrom[i], //enc_context
        transcryptor.getSessionId(), //dec_context
      );
      // TODO: Handle error if pseudonymization fails same as above
    }

    return encryptedPseudonyms;
  }

  public async encryptPseudonym(pseudonym: Pseudonym) {
    if (!this.pepClient) {
      await this.createPEPClient();
    }

    return this.pepClient.encryptPseudonym(pseudonym);
  }

  public async encryptData(datapoint: DataPoint) {
    if (!this.pepClient) {
      await this.createPEPClient();
    }

    return this.pepClient.encryptData(datapoint);
  }

  public async decryptPseudonym(encryptedPseudonym: EncryptedPseudonym) {
    if (!this.pepClient) {
      await this.createPEPClient();
    }

    return this.pepClient.decryptPseudonym(encryptedPseudonym);
  }

  public async decryptData(encryptedData: EncryptedDataPoint) {
    if (!this.pepClient) {
      await this.createPEPClient();
    }

    return this.pepClient.decryptData(encryptedData);
  }

  public getTranscryptorSessionIds() {
    return this.config.transcryptors.map((t) => {
      return {
        transcryptor: t.getSystemId(),
        url: t.getUrl(),
        session: t.getSessionId(),
      };
    });
  }

  public getTranscryptorStatus() {
    return this.config.transcryptors.map((t) => {
      return {
        transcryptor: t.getSystemId(),
        status: t.getStatus(),
      };
    });
  }
}
