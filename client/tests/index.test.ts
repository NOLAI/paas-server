import { exec } from "child_process";
import { promisify } from "util";
const execAsync = promisify(exec);

import {
  PseudonymServiceConfig,
  PEPTranscryptor,
  PseudonymService,
} from "../dist/index";
import { GroupElement } from "@nolai/libpep-wasm";

describe("PaaS js client tests", () => {
  beforeAll(async () => {
    try {
      // Bring up Docker Compose services before tests
      await execAsync("docker-compose up -d", { cwd: "../../example" });
      console.log("Docker services started");
    } catch (error) {
      console.error("Failed to start Docker services:", error);
      throw error;
    }
  });

  test("Create PaaS client", async () => {
    // Test the constructor
    const config: PseudonymServiceConfig = {
      blinded_global_private_key:
        "22e81de441de01e689873e5b7a0c0166f295b75d4bd5b15ad1a5079c919dd007",
      transcryptors: [
        new PEPTranscryptor("http://localhost:8080", "mysecrettoken1"),
        new PEPTranscryptor("http://localhost:8081", "mysecrettoken2"),
        new PEPTranscryptor("http://localhost:8082", "mysecrettoken3"),
      ],
    };

    const pseudonymService = new PseudonymService(config, "domain1", false);

    const random_group_element = GroupElement.random();
    const encrypted = await pseudonymService.encryptPseudonym(
      random_group_element.toHex(),
    );

    const result_random = await pseudonymService.pseudonymize(
      encrypted.toBase64(),
      "domain2",
      "",
      "random",
    );
    const result_regular = await pseudonymService.pseudonymize(
      encrypted.toBase64(),
      "domain2",
      "",
      "default",
    );
    expect(result_random).toEqual(result_regular);
  });

  // More tests...
});
