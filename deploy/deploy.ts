import { ethers } from "hardhat";
import { HardhatRuntimeEnvironment } from "hardhat/types";
import { DeployFunction } from "hardhat-deploy/types";
import { writeFileSync, mkdirSync, existsSync } from "fs";
import path from "path";

const func: DeployFunction = async function (hre: HardhatRuntimeEnvironment) {
  const { deployments, network } = hre;
  const { deploy, getOrNull } = deployments;

  console.log("=".repeat(60));
  console.log("Deploying FHEAuction contract...");
  console.log("Network:", network.name);

  // Kiểm tra mạng
  if (network.name !== "sepolia") {
    throw new Error("This deployment script is configured for Sepolia network only.");
  }

  // LẤY DEPLOYER TỪ PRIVATE_KEY TRONG .ENV
  const [deployerSigner] = await ethers.getSigners();
  const deployer = deployerSigner.address;
  
  console.log("Deployer address:", deployer);

  // Kiểm tra balance deployer
  const balance = await ethers.provider.getBalance(deployer);
  console.log("Deployer balance:", ethers.formatEther(balance), "ETH");
  
  if (balance < ethers.parseEther("0.05")) {
    throw new Error("Insufficient balance for deployer. Need at least 0.05 ETH on Sepolia.");
  }

  // Kiểm tra nếu đã deploy
  const existingDeployment = await getOrNull("FHEAuction");
  if (existingDeployment) {
    console.log("⚠️  FHEAuction already deployed at:", existingDeployment.address);
    console.log("To redeploy, delete the deployment file or use --reset flag");
    return;
  }

  // Tham số cho constructor
  const minDeposit = ethers.parseEther("0.01"); // 0.01 ETH
  const pauserSet = ethers.ZeroAddress; // Không dùng PauserSet
  const beneficiary = deployer; // ✅ Beneficiary = deployer từ PRIVATE_KEY
  const gatewayContract = "0xa02Cda4Ca3a71D7C46997716F4283aa851C28812"; // Sepolia Gateway
  const feeCollector = deployer;

  console.log("\nDeployment parameters:");
  console.log("- Min deposit:", ethers.formatEther(minDeposit), "ETH");
  console.log("- Beneficiary:", beneficiary);
  console.log("- Gateway:", gatewayContract);
  console.log("- PauserSet:", pauserSet);
  console.log("=".repeat(60));
  console.log("- Fee Collector:", feeCollector);

  try {
    // Deploy contract
    console.log("\n🚀 Deploying...");
    
    const deployment = await deploy("FHEAuction", {
      from: deployer,
      args: [minDeposit, pauserSet, beneficiary, gatewayContract, feeCollector],
      log: true,
      autoMine: true,
      gasLimit: 10000000, // Tăng gas limit cho FHE
      // Có thể thêm gasPrice nếu cần
      // gasPrice: ethers.parseUnits("50", "gwei"),
    });

    console.log("\n✅ FHEAuction deployed successfully!");
    console.log("Contract address:", deployment.address);
    console.log("Transaction hash:", deployment.transactionHash);
    console.log("Block number:", deployment.receipt?.blockNumber);
    console.log("Gas used:", deployment.receipt?.gasUsed.toString());

    // Lưu deployment info
    const deploymentsDir = path.join(
      process.cwd(),
      "artifacts",
      "deployments",
      network.name
    );
    
    // Tạo thư mục nếu chưa có
    mkdirSync(deploymentsDir, { recursive: true });

    const deploymentInfo = {
      contractName: "FHEAuction",
      address: deployment.address,
      deployer,
      network: network.name,
      constructor: {
        minDeposit: minDeposit.toString(),
        pauserSet,
        beneficiary,
        gatewayContract,
		feeCollector,
      },
      transaction: {
        hash: deployment.transactionHash,
        blockNumber: deployment.receipt?.blockNumber,
        gasUsed: deployment.receipt?.gasUsed.toString(),
      },
      deploymentDate: new Date().toISOString(),
      abiPath: "./artifacts/contracts/FHEAuction.sol/FHEAuction.json",
      explorer: `https://sepolia.etherscan.io/address/${deployment.address}`,
    };

    const infoPath = path.join(deploymentsDir, "FHEAuction_info.json");
    writeFileSync(infoPath, JSON.stringify(deploymentInfo, null, 2));
    console.log("\n📄 Deployment info saved to:", infoPath);

    // Verify contract info
    console.log("\n🔍 Verifying deployment...");
    const auctionContract = await ethers.getContractAt("FHEAuction", deployment.address);
    
    const auctionInfo = await auctionContract.getAuctionInfo();
    console.log("\nAuction Info:");
    console.log("- Current round:", auctionInfo.round.toString());
    console.log("- Auction state:", ["Active", "Ended", "Finalizing", "Finalized", "Emergency"][auctionInfo.state]);
    console.log("- End time:", new Date(Number(auctionInfo.endTime) * 1000).toLocaleString());
    console.log("- Bidder count:", auctionInfo.maxDeposit.toString());

    const owner = await auctionContract.owner();
    const actualBeneficiary = await auctionContract.beneficiary();
    const actualMinDeposit = await auctionContract.minBidDeposit();
    const actualGateway = await auctionContract.gatewayContract();

    console.log("\nContract Configuration:");
    console.log("- Owner:", owner);
    console.log("- Beneficiary:", actualBeneficiary);
    console.log("- Min deposit:", ethers.formatEther(actualMinDeposit), "ETH");
    console.log("- Gateway:", actualGateway);

    console.log("\n" + "=".repeat(60));
    console.log("✅ DEPLOYMENT SUCCESSFUL!");
    console.log("=".repeat(60));
    console.log("\n📌 Next steps:");
    console.log("1. Verify on Etherscan:");
    console.log(`   npx hardhat verify --network sepolia ${deployment.address} "${minDeposit}" "${pauserSet}" "${beneficiary}" "${gatewayContract}"`);
    console.log("\n2. Test the contract:");
    console.log(`   npx hardhat run scripts/test-auction.ts --network sepolia`);
    console.log("\n3. View on Explorer:");
    console.log(`   https://sepolia.etherscan.io/address/${deployment.address}`);
    console.log("=".repeat(60));

  } catch (error: any) {
    console.error("\n❌ Deployment failed!");
    console.error("Error:", error.message);
    if (error.error) {
      console.error("Details:", error.error);
    }
    throw error;
  }

  return true;
};

func.id = "fheauction-deployment-v2-20251011";
func.tags = ["FHEAuction", "main"];

export default func;