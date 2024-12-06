import {
  PseudonymServiceConfig,
  PEPTranscryptor,
  PseudonymService,
} from "../dist/index";
import {
  BlindedGlobalSecretKey,
  GlobalPublicKey,
  Pseudonym,
} from "@nolai/libpep-wasm";

describe("PaaS js client tests", () => {
  test("Create PaaS client", async () => {
    // Test the constructor
    const configOriginalSender: PseudonymServiceConfig = {
      blindedGlobalPrivateKey: BlindedGlobalSecretKey.fromHex(
        "22e81de441de01e689873e5b7a0c0166f295b75d4bd5b15ad1a5079c919dd007",
      ),
      globalPublicKey: new GlobalPublicKey(),
      transcryptors: [
        new PEPTranscryptor("http://localhost:8080", "mysecrettoken1"),
        new PEPTranscryptor("http://localhost:8081", "mysecrettoken2"),
        new PEPTranscryptor("http://localhost:8082", "mysecrettoken3"),
      ],
    };

    const pseudonymServiceOriginalSender = new PseudonymService(
      configOriginalSender,
      "domain1",
      false,
    );

    const randomGroupElement = Pseudonym.random();
    const encrypted =
      await pseudonymServiceOriginalSender.encryptPseudonym(randomGroupElement);

    const orginalEncryptSession = configOriginalSender.transcryptors.map((t) =>
      t.getSessionId(),
    );

    // ======== encrypted

    const config: PseudonymServiceConfig = {
      blindedGlobalPrivateKey: BlindedGlobalSecretKey.fromHex(
        "22e81de441de01e689873e5b7a0c0166f295b75d4bd5b15ad1a5079c919dd007",
      ),
      globalPublicKey: new GlobalPublicKey(),
      transcryptors: [
        new PEPTranscryptor("http://localhost:8080", "mysecrettoken1"),
        new PEPTranscryptor("http://localhost:8081", "mysecrettoken2"),
        new PEPTranscryptor("http://localhost:8082", "mysecrettoken3"),
      ],
    };

    const pseudonymService = new PseudonymService(config, "domain1", false);

    const resultRandom = await pseudonymService.pseudonymize(
      encrypted,
      "domain2",
      orginalEncryptSession,
      "random",
    );

    const resultRegular = await pseudonymService.pseudonymize(
      encrypted,
      "domain2",
      orginalEncryptSession,
      [0, 1, 2],
    );

    expect(resultRandom.toBase64()).toEqual(resultRegular.toBase64());
  });
});
