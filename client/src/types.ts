import { SessionKeyShare } from "@nolai/libpep-wasm";

export interface StartSessionResponse {
  session_id: string;
  key_share: string;
}
