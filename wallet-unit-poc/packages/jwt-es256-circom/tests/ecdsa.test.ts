import { WitnessTester } from "circomkit";
import { circomkit } from "./common";

describe("ECDSA", () => {
  let circuit: WitnessTester<["s_inverse", "r", "m", "pubKeyX", "pubKeyY"], [""]>;

  describe("ecdsa", () => {
    before(async () => {
      const RECOMPILE = true;
      circuit = await circomkit.WitnessTester(`ECDSA`, {
        file: "ecdsa/ecdsa",
        template: "ECDSA",
        params: [],
        recompile: RECOMPILE,
      });
      console.log("#constraints:", await circuit.getConstraintCount());
    });

    it("testcase-1", async () => {
      const validCase = {
        s_inverse: "86138966109340596411211456067205205974065930252172110859496033749180516610361",
        r: "54464589411922463046224392299866027547594733206525250297420179206855414503921", // Use
        m: "73497146418694151925948476299926153326706551775419257993039383244274530163332", // Zero message
        pubKeyX: "53578245562568858090497762971050088637552636662548898700080252253957930675571",
        pubKeyY: "94717717123739987908966931526384127659809793164315839803856846695569747893398",
      };
      const witness = await circuit.calculateWitness({
        s_inverse: BigInt(validCase.s_inverse),
        r: BigInt(validCase.r),
        m: BigInt(validCase.m),
        pubKeyX: BigInt(validCase.pubKeyX),
        pubKeyY: BigInt(validCase.pubKeyY),
      });

      await circuit.expectConstraintPass(witness);
    });
  });
});
