import resolve from "@rollup/plugin-node-resolve";
import commonjs from "@rollup/plugin-commonjs";
import typescript from "@rollup/plugin-typescript";
import dts from "rollup-plugin-dts";
import { wasm } from "@rollup/plugin-wasm";

export default [
  // ESM Browser Build
  {
    input: "src/index.ts",
    output: {
      file: "dist/paas-client.browser.js",
      format: "es",
    },
    plugins: [
      resolve({ browser: true, preferBuiltins: false }),
      commonjs(),
      typescript(),
      wasm({ targetEnv: "auto-inline" }),
    ],
    // external: ["@nolai/libpep-wasm"],
  },
  // Node.js Build
  {
    input: "src/index.ts",
    output: {
      file: "dist/paas-client.js",
      format: "cjs",
    },
    plugins: [
      resolve({ preferBuiltins: true }),
      commonjs(),
      typescript(),
      wasm(),
    ],
    external: ["@nolai/libpep-wasm"],
  },
  // Type Definitions
  {
    input: "dist/index.d.ts",
    output: {
      file: "dist/index.d.ts",
      format: "es",
    },
    plugins: [dts()],
    external: ["@nolai/libpep-wasm"],
  },
];
