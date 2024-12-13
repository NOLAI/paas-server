import {
  PseudonymServiceConfig,
  PEPTranscryptor,
  PseudonymService,
} from "../dist/paas-client";
import {
  BlindedGlobalSecretKey,
  GlobalPublicKey,
  Pseudonym,
} from "@nolai/libpep-wasm";

describe("PaaS js client tests", () => {
  test("Create PaaS client", async () => {
    const exampleJwt =
      "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ1c2VyMSIsIm5hbWUiOiJKb2huIERvZSIsImdyb3VwcyI6WyJwcm9qZWN0MS1jb29yZGluYXRvciIsInByb2plY3QxLWFuYWx5c3QiXSwiaWF0IjoxNTE2MjM5MDIyLCJleHAiOjE5MjMzMTQ2Mzd9.TjVO51wYydPr_OmQm3NyyX4AeGgV2YqIO1B3sMcGKucp1t8z4qQlTjSi1oiNZixkjD7BtvEbSTTiK9XiujHK3pCltoh8dDq4st6SPkOhiqxolGlQfxC_pL4OJKVicOjtRBCRhXwYYbfhiOJ_xmhpBCNn4VG9YWkuxLrp8q761goTts_Iy-YZFTDgOdRAEXRrkvBVOCUx7sP_lLygN1ArTPK7Rmpjk7Pszo0Eet9oLR11Mu_f5hqQzeSwnoEIoBoSxV6ovHKj9TY_8qT-GJVSg1MMdyDQmFLZYJ_UPeSXFKODak9YuDZ0Z0g2f_amSaxSpZvD1os2rafQ1_G5qW3MN_5rCGMA92rjdY0ObaI5Fa1UllPQwR74eK5ifE7N6vwaYUJhKIYCV3Wrdv__ZHBbLBqnlLdfWGmc2axZvrv76AErzHu1nWOp6EKru_fQkik7vZnFMtFxBX9apni-lLF6j3aWXMR2TIqfaHNAuDvkVX-fW0JUo6PvqaWuv4S-Emm1QL3fZadkNJW3N38Z49qZc8uUA1-Ene1npopDVgk_v49daSwoCUhbC5TkqqjGDbhWJQ8IZu5qVxyLegvpgXEEtvuahS7eB3eK6IVIGbrmezODFpemILj2bMlVCBqHmlhC_spDToKGC215je4pSd5_s_cXjcbbyq7qIIenPAvsmWQ";

    // Test the constructor
    const configOriginalSender: PseudonymServiceConfig = {
      blindedGlobalPrivateKey: BlindedGlobalSecretKey.fromHex(
        "22e81de441de01e689873e5b7a0c0166f295b75d4bd5b15ad1a5079c919dd007",
      ),
      globalPublicKey: {} as GlobalPublicKey,
      transcryptors: [
        new PEPTranscryptor("http://localhost:8080", exampleJwt),
        new PEPTranscryptor("http://localhost:8081", exampleJwt),
        new PEPTranscryptor("http://localhost:8082", exampleJwt),
      ],
    };

    const pseudonymServiceOriginalSender = new PseudonymService(
      configOriginalSender,
      "project1:participant-registration",
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
      globalPublicKey: {} as GlobalPublicKey,
      transcryptors: [
        new PEPTranscryptor("http://localhost:8080", exampleJwt),
        new PEPTranscryptor("http://localhost:8081", exampleJwt),
        new PEPTranscryptor("http://localhost:8082", exampleJwt),
      ],
    };

    const pseudonymService = new PseudonymService(
      config,
      "project1:participant-registration",
      false,
    );

    const resultRandom = await pseudonymService.pseudonymize(
      encrypted,
      "project1:qualtrics",
      orginalEncryptSession,
      "random",
    );

    const resultRegular = await pseudonymService.pseudonymize(
      encrypted,
      "project1:qualtrics",
      orginalEncryptSession,
      [0, 1, 2],
    );

    expect(resultRandom.toBase64()).toEqual(resultRegular.toBase64());
  });
});
