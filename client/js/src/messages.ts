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