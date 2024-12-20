import {
  BlindedGlobalSecretKey,
  DataPoint,
  EncryptedDataPoint,
  EncryptedPseudonym,
  GlobalPublicKey,
  PEPClient,
  Pseudonym,
} from "@nolai/libpep-wasm";
import {PEPTranscryptor} from "./transcryptor.js";

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
        transcryptorId: t.getSystemId(),
        transcryptorUrl: t.getUrl(),
        sessionId: t.getSessionId(),
      };
    });
  }

  public getTranscryptorStatus() {
    return this.config.transcryptors.map((t) => {
      return {
        transcryptorId: t.getSystemId(),
        transcryptorUrl: t.getUrl(),
        status: t.getStatus(),
      };
    });
  }
}
