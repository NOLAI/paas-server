"use strict";
var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
var __generator = (this && this.__generator) || function (thisArg, body) {
    var _ = { label: 0, sent: function() { if (t[0] & 1) throw t[1]; return t[1]; }, trys: [], ops: [] }, f, y, t, g = Object.create((typeof Iterator === "function" ? Iterator : Object).prototype);
    return g.next = verb(0), g["throw"] = verb(1), g["return"] = verb(2), typeof Symbol === "function" && (g[Symbol.iterator] = function() { return this; }), g;
    function verb(n) { return function (v) { return step([n, v]); }; }
    function step(op) {
        if (f) throw new TypeError("Generator is already executing.");
        while (g && (g = 0, op[0] && (_ = 0)), _) try {
            if (f = 1, y && (t = op[0] & 2 ? y["return"] : op[0] ? y["throw"] || ((t = y["return"]) && t.call(y), 0) : y.next) && !(t = t.call(y, op[1])).done) return t;
            if (y = 0, t) op = [op[0] & 2, t.value];
            switch (op[0]) {
                case 0: case 1: t = op; break;
                case 4: _.label++; return { value: op[1], done: false };
                case 5: _.label++; y = op[1]; op = [0]; continue;
                case 7: op = _.ops.pop(); _.trys.pop(); continue;
                default:
                    if (!(t = _.trys, t = t.length > 0 && t[t.length - 1]) && (op[0] === 6 || op[0] === 2)) { _ = 0; continue; }
                    if (op[0] === 3 && (!t || (op[1] > t[0] && op[1] < t[3]))) { _.label = op[1]; break; }
                    if (op[0] === 6 && _.label < t[1]) { _.label = t[1]; t = op; break; }
                    if (t && _.label < t[2]) { _.label = t[2]; _.ops.push(op); break; }
                    if (t[2]) _.ops.pop();
                    _.trys.pop(); continue;
            }
            op = body.call(thisArg, _);
        } catch (e) { op = [6, e]; y = 0; } finally { f = t = 0; }
        if (op[0] & 5) throw op[1]; return { value: op[0] ? op[1] : void 0, done: true };
    }
};
var __spreadArray = (this && this.__spreadArray) || function (to, from, pack) {
    if (pack || arguments.length === 2) for (var i = 0, l = from.length, ar; i < l; i++) {
        if (ar || !(i in from)) {
            if (!ar) ar = Array.prototype.slice.call(from, 0, i);
            ar[i] = from[i];
        }
    }
    return to.concat(ar || Array.prototype.slice.call(from));
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.PseudonymService = exports.PEPTranscryptor = void 0;
var libpep_wasm_1 = require("@nolai/libpep-wasm");
// export interface StartSessionResponse {
//   session_id: string;
//   key_share: SessionKeyShare;
// }
var PEPTranscryptor = /** @class */ (function () {
    function PEPTranscryptor(url, auth_token) {
        this.url = url;
        this.auth_token = auth_token;
        this.status = {
            state: "unknown",
            last_checked: Date.now(),
        };
        this.session_id = null;
    }
    PEPTranscryptor.prototype.check_status = function () {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            var _this = this;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, fetch(this.url + "/status").catch(function (err) {
                            _this.status = {
                                state: "error",
                                last_checked: Date.now(),
                            };
                            return err;
                        })];
                    case 1:
                        response = _a.sent();
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
                        return [2 /*return*/];
                }
            });
        });
    };
    PEPTranscryptor.prototype.start_session = function () {
        return __awaiter(this, void 0, void 0, function () {
            var response, data;
            var _this = this;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, fetch(this.url + "/start_session", {
                            method: "POST",
                            mode: "cors",
                            headers: {
                                "Content-Type": "application/json",
                                Authorization: "Bearer " + this.auth_token,
                            },
                        }).catch(function (err) {
                            _this.status = {
                                state: "error",
                                last_checked: Date.now(),
                            };
                            return err;
                        })];
                    case 1:
                        response = _a.sent();
                        if (!response.ok) return [3 /*break*/, 3];
                        return [4 /*yield*/, response.json()];
                    case 2:
                        data = _a.sent();
                        this.session_id = data.session_id;
                        return [2 /*return*/, data];
                    case 3: throw new Error("Failed to start session with ".concat(this.get_url()));
                }
            });
        });
    };
    PEPTranscryptor.prototype.pseudonymize = function (encrypted_pseudonym, pseudonym_context_from, pseudonym_context_to, enc_context, dec_context) {
        return __awaiter(this, void 0, void 0, function () {
            var response;
            var _this = this;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, fetch(this.url + "/pseudonymize", {
                            method: "POST",
                            mode: "cors",
                            headers: {
                                "Content-Type": "application/json",
                                Authorization: "Bearer " + this.auth_token,
                            },
                            body: JSON.stringify({
                                encrypted_pseudonym: encrypted_pseudonym,
                                pseudonym_context_from: pseudonym_context_from,
                                pseudonym_context_to: pseudonym_context_to,
                                enc_context: enc_context,
                                dec_context: dec_context,
                            }),
                        }).catch(function (err) {
                            _this.status = {
                                state: "error",
                                last_checked: Date.now(),
                            };
                            return err;
                        })];
                    case 1:
                        response = _a.sent();
                        if (!response.ok) return [3 /*break*/, 3];
                        return [4 /*yield*/, response.json()];
                    case 2: return [2 /*return*/, _a.sent()];
                    case 3: return [2 /*return*/];
                }
            });
        });
    };
    PEPTranscryptor.prototype.get_sessions = function () {
        return __awaiter(this, arguments, void 0, function (username) {
            var response;
            var _this = this;
            if (username === void 0) { username = null; }
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, fetch("".concat(this.url, "/get_sessions").concat(username ? "/" + username : ""), {
                            method: "GET",
                            mode: "cors",
                            headers: {
                                "Content-Type": "application/json",
                                Authorization: "Bearer " + this.auth_token,
                            },
                        }).catch(function (err) {
                            _this.status = {
                                state: "error",
                                last_checked: Date.now(),
                            };
                            return err;
                        })];
                    case 1:
                        response = _a.sent();
                        if (!response.ok) return [3 /*break*/, 3];
                        return [4 /*yield*/, response.json()];
                    case 2: return [2 /*return*/, _a.sent()];
                    case 3: return [2 /*return*/];
                }
            });
        });
    };
    PEPTranscryptor.prototype.get_status = function () {
        return this.status;
    };
    PEPTranscryptor.prototype.get_session_id = function () {
        return this.session_id;
    };
    PEPTranscryptor.prototype.get_url = function () {
        return this.url;
    };
    return PEPTranscryptor;
}());
exports.PEPTranscryptor = PEPTranscryptor;
var PseudonymService = /** @class */ (function () {
    function PseudonymService(config, pseudonym_context_to, global) {
        if (global === void 0) { global = false; }
        this.pepClient = null;
        this.config = config;
        this.context_to = pseudonym_context_to;
        this.global = global;
    }
    PseudonymService.prototype.get_transcryptor_order = function (order) {
        if (order === "default") {
            order = __spreadArray([], Array(this.config.transcryptors.length).keys(), true);
        }
        else if (order === "random" || !order) {
            order = __spreadArray([], Array(this.config.transcryptors.length).keys(), true).sort(function () { return Math.random() - 0.5; });
        }
        return order;
    };
    PseudonymService.prototype.createPEPClient = function () {
        return __awaiter(this, void 0, void 0, function () {
            var sks;
            var _this = this;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0: return [4 /*yield*/, Promise.all(this.config.transcryptors.map(function (instance) { return __awaiter(_this, void 0, void 0, function () { return __generator(this, function (_a) {
                            switch (_a.label) {
                                case 0: return [4 /*yield*/, instance.start_session()];
                                case 1: return [2 /*return*/, (_a.sent()).key_share];
                            }
                        }); }); }))];
                    case 1:
                        sks = _a.sent();
                        this.pepClient = new libpep_wasm_1.PEPClient(new libpep_wasm_1.BlindedGlobalSecretKey(libpep_wasm_1.ScalarNonZero.fromHex(this.config.blinded_global_private_key)), sks);
                        return [2 /*return*/];
                }
            });
        });
    };
    PseudonymService.prototype.pseudonymize = function (encrypted_pseudonym, pseudonym_context_from, encryption_context_from, order) {
        return __awaiter(this, void 0, void 0, function () {
            var pseudonym, temp_response, _i, order_1, i, transcryptor;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        pseudonym = new libpep_wasm_1.EncryptedPseudonym(libpep_wasm_1.ElGamal.fromBase64(encrypted_pseudonym));
                        if (!!this.pepClient) return [3 /*break*/, 2];
                        return [4 /*yield*/, this.createPEPClient()];
                    case 1:
                        _a.sent();
                        _a.label = 2;
                    case 2:
                        order = this.get_transcryptor_order(order);
                        temp_response = pseudonym;
                        _i = 0, order_1 = order;
                        _a.label = 3;
                    case 3:
                        if (!(_i < order_1.length)) return [3 /*break*/, 6];
                        i = order_1[_i];
                        transcryptor = this.config.transcryptors[i];
                        return [4 /*yield*/, transcryptor.pseudonymize(temp_response, //encrypted_pseudonym
                            pseudonym_context_from, //pseudonym_context_from
                            this.context_to, //pseudonym_context_to
                            encryption_context_from, //enc_context
                            transcryptor.get_session_id())];
                    case 4:
                        temp_response = _a.sent();
                        _a.label = 5;
                    case 5:
                        _i++;
                        return [3 /*break*/, 3];
                    case 6: return [2 /*return*/, temp_response];
                }
            });
        });
    };
    PseudonymService.prototype.pseudonymize_batch = function () {
        return __awaiter(this, void 0, void 0, function () { return __generator(this, function (_a) {
            return [2 /*return*/];
        }); });
    }; // TODO: Job vragen
    PseudonymService.prototype.encryptPseudonym = function (pseudonym) {
        return __awaiter(this, void 0, void 0, function () {
            var pseudonym_wasm;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        pseudonym_wasm = libpep_wasm_1.Pseudonym.fromHex(pseudonym);
                        if (!!this.pepClient) return [3 /*break*/, 2];
                        return [4 /*yield*/, this.createPEPClient()];
                    case 1:
                        _a.sent();
                        _a.label = 2;
                    case 2: return [2 /*return*/, this.pepClient.encryptPseudonym(pseudonym_wasm)];
                }
            });
        });
    };
    PseudonymService.prototype.encryptData = function (data) {
        return __awaiter(this, void 0, void 0, function () {
            var datapoint;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        datapoint = new libpep_wasm_1.DataPoint(libpep_wasm_1.GroupElement.fromHex(data));
                        if (!!this.pepClient) return [3 /*break*/, 2];
                        return [4 /*yield*/, this.createPEPClient()];
                    case 1:
                        _a.sent();
                        _a.label = 2;
                    case 2: return [2 /*return*/, this.pepClient.encryptData(datapoint)];
                }
            });
        });
    };
    PseudonymService.prototype.decryptPseudonym = function (encryptedPseudonym) {
        return __awaiter(this, void 0, void 0, function () {
            var encryptedPseudonymWasm;
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        encryptedPseudonymWasm = new libpep_wasm_1.EncryptedPseudonym(libpep_wasm_1.ElGamal.fromBase64(encryptedPseudonym));
                        if (!!this.pepClient) return [3 /*break*/, 2];
                        return [4 /*yield*/, this.createPEPClient()];
                    case 1:
                        _a.sent();
                        _a.label = 2;
                    case 2: return [2 /*return*/, this.pepClient.decryptPseudonym(encryptedPseudonymWasm)];
                }
            });
        });
    };
    PseudonymService.prototype.decryptData = function (encryptedData) {
        return __awaiter(this, void 0, void 0, function () {
            return __generator(this, function (_a) {
                switch (_a.label) {
                    case 0:
                        if (!!this.pepClient) return [3 /*break*/, 2];
                        return [4 /*yield*/, this.createPEPClient()];
                    case 1:
                        _a.sent();
                        _a.label = 2;
                    case 2: return [2 /*return*/, this.pepClient.decryptData(encryptedData)];
                }
            });
        });
    };
    return PseudonymService;
}());
exports.PseudonymService = PseudonymService;
