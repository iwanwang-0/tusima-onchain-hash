const {
    time,
    loadFixture,
  } = require("@nomicfoundation/hardhat-network-helpers");
  const { anyValue } = require("@nomicfoundation/hardhat-chai-matchers/withArgs");
  const { expect } = require("chai");
  
  describe("OnchainHahCompute", function () {
    // We define a fixture to reuse the same setup in every test.
    // We use loadFixture to run this setup once, snapshot that state,
    // and reset Hardhat Network to that snapshot in every test.
    async function deployOneYearLockFixture() {
      // Contracts are deployed using the first signer/account by default
      const [owner, otherAccount] = await ethers.getSigners();

      const poseidonUnit = require("../node_modules/circomlib/src/poseidon_gencontract.js");

      console.log(poseidonUnit.createCode());

      // 常见合约工厂实例
      let factory = new ethers.ContractFactory(poseidonUnit.abi, poseidonUnit.createCode(), owner);

      // 请注意，我们将 "Hello World" 作为参数传递给合约构造函数constructor
      let contract = await factory.deploy();

      contract("------ poseidon contract: " + contract.address);
  
      const OnchainHahCompute = await ethers.getContractFactory("OnchainHahCompute");
      const onchainHahCompute = await OnchainHahCompute.deploy(contract.address);
  
      return onchainHahCompute;
    }
  
    describe("Deployment", function () {
      it("Should set the right unlockTime", async function () {
        // const onchainHahCompute = await loadFixture(deployOneYearLockFixture);
        // const onchainHahCompute = await deployOneYearLockFixture();
  
        // expect(await lock.unlockTime()).to.equal(unlockTime);
      });
    });
  
  });
  