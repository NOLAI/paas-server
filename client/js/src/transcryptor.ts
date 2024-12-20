import {EncryptedPseudonym, SessionKeyShare} from "@nolai/libpep-wasm";
import {
    GetSessionResponse,
    PseudonymizationBatchRequest, PseudonymizationBatchResponse,
    PseudonymizationRequest, PseudonymizationResponse,
    StartSessionResponse,
    StatusResponse
} from "./messages.js";


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
                encrypted_pseudonym: encryptedPseudonym.asBase64(),
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
                encrypted_pseudonyms: encryptedPseudonym.map((p) => p.asBase64()),
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