import {
    BlindedGlobalSecretKey,
    DataPoint,
    EncryptedDataPoint,
    EncryptedPseudonym,
    GlobalPublicKey,
    PEPClient,
    Pseudonym,
    SessionKeyShare
} from "@nolai/libpep-wasm";

export type PseudonymizationDomain = string;
export type EncryptionContext = string;
export type SystemId = string;

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
    domain_from: string;
    domain_to: string;
    session_from: string;
    session_to: string;
}

export interface PseudonymizationBatchRequest {
    encrypted_pseudonyms: string[];
    domain_from: string;
    domain_to: string;
    session_from: string;
    session_to: string;
}

export interface PseudonymizationBatchResponse {
    encrypted_pseudonyms: string[];
}



export class TranscryptorConfig {
    public systemId: string;
    public url: string;

    public constructor(systemId: string, url: string) {
        this.systemId = systemId;
        this.url = url;
    }
}

export enum TranscryptorState {
    UNKNOWN = "unknown",
    ONLINE = "online",
    OFFLINE = "offline",
    ERROR = "error",
}

export class TranscryptorStatus {
    private state: string;
    private lastChecked: number;

    public constructor(state: TranscryptorState, lastChecked: number) {
        this.state = state;
        this.lastChecked = lastChecked;
    }
}

export class Transcryptor {
    private config: TranscryptorConfig;
    public authToken: AuthToken;
    private status: TranscryptorStatus;
    private sessionId: string | null;

    public constructor(config: TranscryptorConfig, authToken: AuthToken) {
        this.config = config;
        this.authToken = authToken;
        this.status = new TranscryptorStatus(TranscryptorState.UNKNOWN, Date.now());
        this.sessionId = null;
    }

    public async checkStatus() {
        const response = await fetch(this.config.url + "/status", {
            method: "GET",
            mode: "cors",
            headers: {
                Authorization: "Bearer " + this.authToken,
            },
        }).catch((err) => {
            this.status = new TranscryptorStatus(TranscryptorState.ERROR, Date.now());
            return err;
        }); // TODO check session id

        if (!response.ok) {
            this.status = new TranscryptorStatus(
                response.status === 404
                    ? TranscryptorState.OFFLINE
                    : TranscryptorState.ERROR,
                Date.now(),
            );
        } else {
            this.status = new TranscryptorStatus(
                TranscryptorState.ONLINE,
                Date.now(),
            );
        }
    }

    public async startSession() {
        const response = await fetch(this.config.url + "/sessions/start", {
            method: "POST",
            mode: "cors",
            headers: {
                "Content-Type": "application/json",
                Authorization: "Bearer " + this.authToken,
            },
        }).catch((err) => {
            this.status = new TranscryptorStatus(TranscryptorState.ERROR, Date.now());
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
            throw new Error(
                `Failed to start session with ${this.config.systemId} at ${this.config.url}`,
            );
        }
    }

    public async pseudonymize(
        encryptedPseudonym: EncryptedPseudonym,
        domainFrom: PseudonymizationDomain,
        domainTo: PseudonymizationDomain,
        sessionFrom: EncryptionContext,
        sessionTo: EncryptionContext,
    ): Promise<EncryptedPseudonym> {
        const response = await fetch(this.config.url + "/pseudonymize", {
            method: "POST",
            mode: "cors",
            headers: {
                "Content-Type": "application/json",
                Authorization: "Bearer " + this.authToken,
            },
            body: JSON.stringify({
                // eslint-disable-next-line camelcase
                encrypted_pseudonym: encryptedPseudonym.asBase64(),
                // eslint-disable-next-line camelcase
                domain_from: domainFrom,
                // eslint-disable-next-line camelcase
                domain_to: domainTo,
                // eslint-disable-next-line camelcase
                session_from: sessionFrom,
                // eslint-disable-next-line camelcase
                session_to: sessionTo,
            } as PseudonymizationRequest),
        }).catch((err) => {
            this.status = new TranscryptorStatus(TranscryptorState.ERROR, Date.now());
            return err;
        });

        if (response.ok) {
            const data: PseudonymizationResponse = await response.json();
            return EncryptedPseudonym.fromBase64(data.encrypted_pseudonym);
        }
    }

    public async pseudonymizeBatch(
        encryptedPseudonyms: EncryptedPseudonym[],
        domainFrom: PseudonymizationDomain,
        domainTo: PseudonymizationDomain,
        sessionFrom: EncryptionContext,
        sessionTo: EncryptionContext,
    ): Promise<EncryptedPseudonym[]> {
        const response = await fetch(this.config.url + "/pseudonymize", {
            method: "POST",
            mode: "cors",
            headers: {
                "Content-Type": "application/json",
                Authorization: "Bearer " + this.authToken,
            },
            body: JSON.stringify({
                // eslint-disable-next-line camelcase
                encrypted_pseudonyms: encryptedPseudonyms.map((p) => p.asBase64()),
                // eslint-disable-next-line camelcase
                domain_from: domainFrom,
                // eslint-disable-next-line camelcase
                domain_to: domainTo,
                // eslint-disable-next-line camelcase
                session_from: sessionFrom,
                // eslint-disable-next-line camelcase
                session_to: sessionTo,
            } as PseudonymizationBatchRequest),
        }).catch((err) => {
            this.status = new TranscryptorStatus(TranscryptorState.ERROR, Date.now());
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
            `${this.config.url}/sessions/get${username ? "/" + username : ""}`,
            {
                method: "GET",
                mode: "cors",
                headers: {
                    "Content-Type": "application/json",
                    Authorization: "Bearer " + this.authToken,
                },
            },
        ).catch((err) => {
            this.status = new TranscryptorStatus(TranscryptorState.ERROR, Date.now());
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
        return this.config.url;
    }

    public getSystemId() {
        return this.config.systemId;
    }
}


export interface PseudonymServiceConfig {
    blindedGlobalPrivateKey: BlindedGlobalSecretKey;
    globalPublicKey: GlobalPublicKey;
    transcryptors: TranscryptorConfig[];
}

export type EncryptionContexts = Map<SystemId, EncryptionContext>;
export type AuthToken = string;

export class PseudonymService {
    private config: PseudonymServiceConfig;
    private transcryptors: Transcryptor[];
    private pepCryptoClient: PEPClient | null = null;

    public constructor(
        config: PseudonymServiceConfig,
        authTokens: Map<SystemId, AuthToken>,
    ) {
        this.config = config;
        this.transcryptors = config.transcryptors.map(
            (c) => new Transcryptor(c, authTokens.get(c.systemId)),
        );
    }

    public async init() {
        const sks = await Promise.all(
            this.transcryptors.map(async (t) => (await t.startSession()).keyShare),
        );
        this.pepCryptoClient = new PEPClient(
            this.config.blindedGlobalPrivateKey,
            sks,
        );
    }

    // private getTranscryptorOrder(order: "random" | "default" | number[]) {
    //   if (order === "default") {
    //     order = [...Array(this.config.transcryptors.length).keys()];
    //   } else if (order === "random" || !order) {
    //     order = [...Array(this.config.transcryptors.length).keys()].sort(
    //       () => Math.random() - 0.5,
    //     );
    //   }
    //   return order;
    // }

    public async pseudonymize(
        encryptedPseudonym: EncryptedPseudonym,
        sessionsFrom: EncryptionContexts,
        domainFrom: PseudonymizationDomain,
        domainTo: PseudonymizationDomain,
        // order?: "random" | number[], //TODO: I don't think default is the right word here
    ) {
        if (!this.pepCryptoClient) {
            await this.init();
        }

        // order = this.getTranscryptorOrder(order);

        for (const transcryptor of this.transcryptors) {
            let response = await transcryptor.pseudonymize(
                encryptedPseudonym,
                domainFrom,
                domainTo,
                sessionsFrom.get(transcryptor.getSystemId()),
                transcryptor.getSessionId(),
            );
            encryptedPseudonym = response;
            // TODO: Handle error if pseudonymization fails
        }

        return encryptedPseudonym;
    }

    public async pseudonymizeBatch(
        encryptedPseudonyms: EncryptedPseudonym[],
        sessionsFrom: EncryptionContexts,
        domainFrom: PseudonymizationDomain,
        domainTo: PseudonymizationDomain,
        // order?: "random" | number[], //TODO: I don't think default is the right word here
    ) {
        if (!this.pepCryptoClient) {
            await this.init();
        }

        // order = this.getTranscryptorOrder(order);

        for (const transcryptor of this.transcryptors) {
            encryptedPseudonyms = await transcryptor.pseudonymizeBatch(
                encryptedPseudonyms,
                domainFrom,
                domainTo,
                sessionsFrom.get(transcryptor.getSystemId()),
                transcryptor.getSessionId(),
            );
            // TODO: Handle error if pseudonymization fails
        }

        return encryptedPseudonyms;
    }

    public async encryptPseudonym(pseudonym: Pseudonym) {
        if (!this.pepCryptoClient) {
            await this.init();
        }

        return this.pepCryptoClient.encryptPseudonym(pseudonym);
    }

    public async encryptData(datapoint: DataPoint) {
        if (!this.pepCryptoClient) {
            await this.init();
        }

        return this.pepCryptoClient.encryptData(datapoint);
    }

    public async decryptPseudonym(encryptedPseudonym: EncryptedPseudonym) {
        if (!this.pepCryptoClient) {
            await this.init();
        }

        return this.pepCryptoClient.decryptPseudonym(encryptedPseudonym);
    }

    public async decryptData(encryptedData: EncryptedDataPoint) {
        if (!this.pepCryptoClient) {
            await this.init();
        }

        return this.pepCryptoClient.decryptData(encryptedData);
    }

    public getCurrentSessions(): EncryptionContexts {
        return new Map(
            this.transcryptors.map((t) => [t.getSystemId(), t.getSessionId()]),
        );
    }

    public getTranscryptorStatus() {
        return this.transcryptors.map((t) => t.getStatus());
    }
}
