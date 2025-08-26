/* eslint-env node */
import { config } from "dotenv";
import express, { Request, Response } from "express";
import { verify, settle } from "x402/facilitator";
import {
  PaymentRequirementsSchema,
  type PaymentRequirements,
  type PaymentPayload,
  PaymentPayloadSchema,
  createConnectedClient,
  createSigner,
  SupportedEVMNetworks,
  SupportedSVMNetworks,
  Signer,
  ConnectedClient,
  SupportedPaymentKind,
  isSvmSignerWallet,
  sui,
} from "x402/types";

config();

const EVM_PRIVATE_KEY = process.env.EVM_PRIVATE_KEY || "";
const SVM_PRIVATE_KEY = process.env.SVM_PRIVATE_KEY || "";
const SUI_MAINNET_RPC_URL = process.env.SUI_MAINNET_RPC_URL || "";
const SUI_TESTNET_RPC_URL =
  process.env.SUI_TESTNET_RPC_URL || "https://fullnode.testnet.sui.io:443";

// if (!EVM_PRIVATE_KEY && !SVM_PRIVATE_KEY && !SUI_MAINNET_RPC_URL) {
//   // TODO: should this indicate the missing environment variables, and should they all be required?
//   // Code below assumes they are all set
//   console.error("Missing required environment variables");
//   process.exit(1);
// }

const app = express();

// Configure express to parse JSON bodies
app.use(express.json());

type VerifyRequest = {
  paymentPayload: PaymentPayload;
  paymentRequirements: PaymentRequirements;
};

type SettleRequest = {
  paymentPayload: PaymentPayload;
  paymentRequirements: PaymentRequirements;
};

app.post("/verify", async (req: Request, res: Response) => {
  console.log("[VERIFY] Received verify request");
  console.log("[VERIFY] Payment payload:", JSON.stringify(req.body.paymentPayload, null, 2));
  console.log("[VERIFY] Payment requirements:", JSON.stringify(req.body.paymentRequirements, null, 2));
  
  try {
    const body: VerifyRequest = req.body;
    const paymentRequirements = PaymentRequirementsSchema.parse(body.paymentRequirements);
    const paymentPayload = PaymentPayloadSchema.parse(body.paymentPayload);

    console.log("[VERIFY] Parsed successfully. Network:", paymentRequirements.network);
    console.log("[VERIFY] Payment payload network:", paymentPayload.network);
    if ("authorization" in paymentPayload.payload) {
      console.log("[VERIFY] Authorization nonce:", paymentPayload.payload.authorization.nonce);
    }

    // use the correct client/signer based on the requested network
    // svm verify requires a Signer because it signs & simulates the txn
    let client: Signer | ConnectedClient;
    if (SupportedEVMNetworks.includes(paymentRequirements.network)) {
      console.log("[VERIFY] Using EVM network:", paymentRequirements.network);
      client = createConnectedClient(paymentRequirements.network);
    } else if (SupportedSVMNetworks.includes(paymentRequirements.network)) {
      console.log("[VERIFY] Using SVM network:", paymentRequirements.network);
      client = await createSigner(paymentRequirements.network, SVM_PRIVATE_KEY);
    } else if (paymentPayload.network === "sui-testnet") {
      console.log("[VERIFY] Using Sui testnet");
      client = sui.createClient(paymentRequirements.network, SUI_TESTNET_RPC_URL);
    } else if (paymentPayload.network === "sui") {
      console.log("[VERIFY] Using Sui mainnet");
      client = sui.createClient(paymentRequirements.network, SUI_MAINNET_RPC_URL);
    } else {
      throw new Error("Invalid network");
    }

    console.log("[VERIFY] Starting verification...");
    // verify
    const valid = await verify(client, paymentPayload, paymentRequirements);
    console.log("[VERIFY] Verification result:", JSON.stringify(valid, null, 2));
    res.json(valid);
  } catch (error) {
    console.error("[VERIFY] Error:", error);
    res.status(400).json({ error: "Invalid request" });
  }
});

app.get("/settle", (req: Request, res: Response) => {
  res.json({
    endpoint: "/settle",
    description: "POST to settle x402 payments",
    body: {
      paymentPayload: "PaymentPayload",
      paymentRequirements: "PaymentRequirements",
    },
  });
});

app.get("/supported", async (req: Request, res: Response) => {
  let kinds: SupportedPaymentKind[] = [];

  // evm
  if (EVM_PRIVATE_KEY) {
    kinds.push({
      x402Version: 1,
      scheme: "exact",
      network: "base-sepolia",
    });
  }

  // svm
  if (SVM_PRIVATE_KEY) {
    const signer = await createSigner("solana-devnet", SVM_PRIVATE_KEY);
    const feePayer = isSvmSignerWallet(signer) ? signer.address : undefined;

    kinds.push({
      x402Version: 1,
      scheme: "exact",
      network: "solana-devnet",
      extra: {
        feePayer,
      },
    });
  }
  res.json({
    kinds,
  });
});

app.post("/settle", async (req: Request, res: Response) => {
  console.log("[SETTLE] Received settle request");
  console.log("[SETTLE] Payment payload:", JSON.stringify(req.body.paymentPayload, null, 2));
  console.log("[SETTLE] Payment requirements:", JSON.stringify(req.body.paymentRequirements, null, 2));
  
  try {
    const body: SettleRequest = req.body;
    const paymentRequirements = PaymentRequirementsSchema.parse(body.paymentRequirements);
    const paymentPayload = PaymentPayloadSchema.parse(body.paymentPayload);

    console.log("[SETTLE] Parsed successfully. Network:", paymentRequirements.network);
    console.log("[SETTLE] Payment payload network:", paymentPayload.network);
    if ("authorization" in paymentPayload.payload) {
      console.log("[SETTLE] Authorization nonce:", paymentPayload.payload.authorization.nonce);
    }

    // use the correct private key based on the requested network
    let signerOrClient: Signer | ConnectedClient;
    if (SupportedEVMNetworks.includes(paymentRequirements.network)) {
      console.log("[SETTLE] Using EVM network signer:", paymentRequirements.network);
      signerOrClient = await createSigner(paymentRequirements.network, EVM_PRIVATE_KEY);
    } else if (SupportedSVMNetworks.includes(paymentRequirements.network)) {
      console.log("[SETTLE] Using SVM network signer:", paymentRequirements.network);
      signerOrClient = await createSigner(paymentRequirements.network, SVM_PRIVATE_KEY);
    } else if (paymentPayload.network === "sui-testnet") {
      console.log("[SETTLE] Using Sui testnet client");
      signerOrClient = sui.createClient(paymentRequirements.network, SUI_TESTNET_RPC_URL);
    } else if (paymentPayload.network === "sui") {
      console.log("[SETTLE] Using Sui mainnet client");
      signerOrClient = sui.createClient(paymentRequirements.network, SUI_MAINNET_RPC_URL);
    } else {
      throw new Error("Invalid network");
    }

    console.log("[SETTLE] Starting settlement...");
    // settle
    const response = await settle(signerOrClient, paymentPayload, paymentRequirements);
    console.log("[SETTLE] Settlement result:", JSON.stringify(response, null, 2));
    res.json(response);
  } catch (error) {
    console.error("[SETTLE] Error:", error);
    res.status(400).json({ error: `Invalid request: ${error}` });
  }
});

app.listen(process.env.PORT || 3000, () => {
  console.log(`Server listening at http://localhost:${process.env.PORT || 3000}`);
});
