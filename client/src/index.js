var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
import { BlindedGlobalSecretKey, ElGamal, EncryptedPseudonym, PEPClient, ScalarNonZero, } from "@nolai/libpep-wasm";
export class PEPTranscryptor {
    constructor(url, auth_token) {
        this.url = url;
        this.auth_token = auth_token;
        this.status = {
            state: "unknown",
            last_checked: Date.now(),
        };
        this.session_id = null;
    }
    check_status() {
        return __awaiter(this, void 0, void 0, function* () {
            const response = yield fetch(this.url + "/status").catch((err) => {
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
            }
            else {
                this.status = {
                    state: "online",
                    last_checked: Date.now(),
                };
            }
        });
    }
    start_session() {
        return __awaiter(this, void 0, void 0, function* () {
            const response = yield fetch(this.url + "/start_session", {
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
                const data = yield response.json();
                this.session_id = data.session_id;
                return data;
            }
            else {
                throw new Error(`Failed to start session with ${this.get_url()}`);
            }
        });
    }
    pseudonymize(encrypted_pseudonym, pseudonym_context_from, pseudonym_context_to, enc_context, dec_context) {
        return __awaiter(this, void 0, void 0, function* () {
            const response = yield fetch(this.url + "/pseudonymize", {
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
                return yield response.json();
            }
        });
    }
    get_sessions() {
        return __awaiter(this, arguments, void 0, function* (username = null) {
            const response = yield fetch(`${this.url}/get_sessions${username ? "/" + username : ""}`, {
                method: "GET",
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
                return yield response.json();
            }
        });
    }
    get_status() {
        return this.status;
    }
    get_session_id() {
        return this.session_id;
    }
    get_url() {
        return this.url;
    }
}
export class PseudonymService {
    constructor(config, pseudonym_context_to, global = false) {
        this.pepClient = null;
        this.config = config;
        this.context_to = pseudonym_context_to;
        this.global = global;
    }
    createPEPClient() {
        return __awaiter(this, void 0, void 0, function* () {
            const sks = yield Promise.all(this.config.transcryptors.map((instance) => __awaiter(this, void 0, void 0, function* () { return (yield instance.start_session()).key_share; })));
            this.pepClient = new PEPClient(new BlindedGlobalSecretKey(ScalarNonZero.fromHex(this.config.blinded_global_private_key)), sks);
        });
    }
    pseudonymize(encrypted_pseudonym, pseudonym_context_from, encryption_context_from, order) {
        return __awaiter(this, void 0, void 0, function* () {
            // TODO: maybe check if pseudonym is base64 encoded
            const pseudonym = new EncryptedPseudonym(ElGamal.fromBase64(encrypted_pseudonym));
            if (!this.pepClient) {
                yield this.createPEPClient();
            }
            if (order === "default") {
                order = [...Array(this.config.transcryptors.length).keys()];
            }
            else if (order === "random" || !order) {
                order = [...Array(this.config.transcryptors.length).keys()].sort(() => Math.random() - 0.5);
            }
            let temp_response = pseudonym;
            for (const i of order) {
                const transcryptor = this.config.transcryptors[i];
                temp_response = yield transcryptor.pseudonymize(
                // encrypted_pseudonym: EncryptedPseudonym,
                // pseudonym_context_from: string,
                // pseudonym_context_to: string,
                // enc_context: string,
                // dec_context: string,
                temp_response, pseudonym_context_from, this.context_to, encryption_context_from, pseudonym_context_from);
            }
            return temp_response;
        });
    }
    pseudonymize_batch() {
        return __awaiter(this, void 0, void 0, function* () { });
    }
    rerandomize() {
        return __awaiter(this, void 0, void 0, function* () { });
    }
    encrypt() {
        return __awaiter(this, void 0, void 0, function* () { });
    }
    decrypt() {
        return __awaiter(this, void 0, void 0, function* () { });
    }
}
