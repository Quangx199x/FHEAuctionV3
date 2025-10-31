// scripts/getPublicKeyNode.mjs
import { JsonRpcProvider } from 'ethers';
import { initFhevm, createInstance } from '@fhevm/sdk';
import dotenv from 'dotenv';

dotenv.config();

async function getPublicKey() {
  console.log(`🔍 Đang lấy Public Key FHE từ Sepolia...`);
  console.log(`🌐 RPC: ${process.env.SEPOLIA_RPC_URL}`);

  try {
    // Bước 1: Khởi tạo FHEVM SDK
    console.log('⏳ Initializing FHEVM...');
    await initFhevm();
    console.log('✅ FHEVM SDK initialized.');

    // Bước 2: Tạo provider trực tiếp từ RPC URL
    const provider = new JsonRpcProvider(process.env.SEPOLIA_RPC_URL);
    console.log('✅ Provider connected.');

    // Bước 3: Tạo instance
    console.log('⏳ Creating instance...');
    const instance = await createInstance({
      provider,
      verifyingContractAddress: "0x7048C39f048125eDa9d678AEbaDfB22F7900a29F",
      kmsContractAddress: "0x1364cBBf2cDF5032C47d8226a6f6FBD2AFCDacAC",
      aclContractAddress: "0x687820221192C5B662b25367F70076A37bc79b6c",
      relayerUrl: "https://relayer.testnet.zama.cloud",
      gatewayUrl: "https://gateway.sepolia.zama.ai/",
      gatewayChainId: 11155111,
    });
    console.log('✅ Instance created successfully.');

    // Bước 4: Lấy public key
    const fhePublicKey = instance.publicKey;
    if (!fhePublicKey) {
      throw new Error('Public key không khả dụng.');
    }

    console.log("-----------------------------------------");
    console.log("✅ SUCCESS! Public Key FHE đã lấy thành công!");
    console.log('📝 Public Key FHE:');
    console.log(fhePublicKey);
    console.log('✂️ Copy vào code:');
    console.log(`const PUBLIC_KEY = '${fhePublicKey}';`);
    console.log("-----------------------------------------");

  } catch (error) {
    console.error("❌ Lỗi:");
    console.error(error.message);
    process.exit(1);
  }
}

getPublicKey();