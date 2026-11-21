import { expect } from 'chai';
import { network } from 'hardhat';
import { anyValue } from '@nomicfoundation/hardhat-ethers-chai-matchers/withArgs';

const { ethers } = await network.create();

describe('CronosBridgeVault', function () {
  const routeId = ethers.id('XTC:CRONOS:25:XITCOIN');
  const maxRelease = ethers.parseEther('100');
  const dailyLimit = ethers.parseEther('150');
  const maxDeposit = ethers.parseEther('50');
  const dailyDepositLimit = ethers.parseEther('120');
  const maxLocked = ethers.parseEther('700');
  const deadAddress = '0x000000000000000000000000000000000000dEaD';

  let deployer;
  let user;
  let recipient;
  let signerOne;
  let signerTwo;
  let signerThree;
  let guardian;
  let outsider;
  let replacementOne;
  let replacementTwo;
  let replacementThree;
  let token;
  let vault;

  async function deadline(offset = 3600n) {
    const block = await ethers.provider.getBlock('latest');
    return BigInt(block.timestamp) + offset;
  }

  async function domain(target = vault) {
    const network = await ethers.provider.getNetwork();
    return {
      name: 'Xitcoin Cronos Bridge Vault',
      version: '1',
      chainId: network.chainId,
      verifyingContract: await target.getAddress()
    };
  }

  const releaseTypes = {
    Release: [
      { name: 'sourceBurnId', type: 'bytes32' },
      { name: 'recipient', type: 'address' },
      { name: 'amount', type: 'uint256' },
      { name: 'signerSetVersion', type: 'uint64' },
      { name: 'deadline', type: 'uint256' }
    ]
  };

  const controlTypes = {
    Control: [
      { name: 'action', type: 'bytes32' },
      { name: 'payloadHash', type: 'bytes32' },
      { name: 'nonce', type: 'uint256' },
      { name: 'signerSetVersion', type: 'uint64' },
      { name: 'deadline', type: 'uint256' }
    ]
  };

  async function signRelease({
    sourceBurnId,
    to = recipient.address,
    amount = ethers.parseEther('10'),
    version = 1n,
    expires,
    signers = [signerOne, signerTwo],
    target = vault
  }) {
    const expiry = expires ?? await deadline();
    const value = {
      sourceBurnId,
      recipient: to,
      amount,
      signerSetVersion: version,
      deadline: expiry
    };
    const signingDomain = await domain(target);
    const signatures = [];
    for (const signer of signers) {
      signatures.push(
        await signer.signTypedData(signingDomain, releaseTypes, value)
      );
    }
    return { expiry, signatures };
  }

  async function signControl({
    action,
    payloadHash = ethers.ZeroHash,
    nonce,
    version,
    expires,
    signers = [signerOne, signerTwo]
  }) {
    const controlNonce = nonce ?? await vault.governanceNonce();
    const signerVersion = version ?? await vault.signerSetVersion();
    const expiry = expires ?? await deadline();
    const value = {
      action,
      payloadHash,
      nonce: controlNonce,
      signerSetVersion: signerVersion,
      deadline: expiry
    };
    const signingDomain = await domain();
    const signatures = [];
    for (const signer of signers) {
      signatures.push(
        await signer.signTypedData(signingDomain, controlTypes, value)
      );
    }
    return {
      nonce: controlNonce,
      expiry,
      signatures
    };
  }

  async function deployVault(overrides = {}) {
    const Vault = await ethers.getContractFactory('CronosBridgeVault');
    const config = {
      maxRelease,
      dailyLimit,
      maxDeposit,
      dailyDepositLimit,
      maxLocked,
      paused: false,
      ...overrides
    };
    return Vault.deploy(
      await token.getAddress(),
      routeId,
      [signerOne.address, signerTwo.address, signerThree.address],
      guardian.address,
      config.maxRelease,
      config.dailyLimit,
      config.maxDeposit,
      config.dailyDepositLimit,
      config.maxLocked,
      config.paused
    );
  }

  function depositLimitsPayload(maximum, daily, locked) {
    return ethers.keccak256(
      ethers.AbiCoder.defaultAbiCoder().encode(
        ['uint256', 'uint256', 'uint256'],
        [maximum, daily, locked]
      )
    );
  }

  async function nextTimestamp(timestamp) {
    await ethers.provider.send('evm_setNextBlockTimestamp', [Number(timestamp)]);
  }

  async function latestTimestamp() {
    return BigInt((await ethers.provider.getBlock('latest')).timestamp);
  }

  async function approveAndDeposit(amount, options = {}) {
    await token.connect(user).approve(await vault.getAddress(), amount);
    return vault.connect(user).deposit(amount, recipient.address, options);
  }

  async function releaseSigned(sourceBurnId, amount) {
    const signed = await signRelease({ sourceBurnId, amount });
    return vault.release(
      sourceBurnId,
      recipient.address,
      amount,
      1,
      signed.expiry,
      signed.signatures
    );
  }

  beforeEach(async function () {
    [
      deployer,
      user,
      recipient,
      signerOne,
      signerTwo,
      signerThree,
      guardian,
      outsider,
      replacementOne,
      replacementTwo,
      replacementThree
    ] = await ethers.getSigners();

    const Token = await ethers.getContractFactory('MockERC20');
    token = await Token.deploy('Xitcoin', 'XTC');

    const Vault = await ethers.getContractFactory('CronosBridgeVault');
    vault = await Vault.deploy(
      await token.getAddress(),
      routeId,
      [signerOne.address, signerTwo.address, signerThree.address],
      guardian.address,
      maxRelease,
      dailyLimit,
      maxDeposit,
      dailyDepositLimit,
      maxLocked,
      false
    );

    await token.mint(user.address, ethers.parseEther('1000'));
    await token.mint(await vault.getAddress(), ethers.parseEther('500'));
  });

  describe('deployment', function () {
    it('stores the canonical asset, route, signer set and limits', async function () {
      expect(await vault.asset()).to.equal(await token.getAddress());
      expect(await vault.routeId()).to.equal(routeId);
      expect(await vault.signers()).to.deep.equal([
        signerOne.address,
        signerTwo.address,
        signerThree.address
      ]);
      expect(await vault.signerSetVersion()).to.equal(1n);
      expect(await vault.guardian()).to.equal(guardian.address);
      expect(await vault.maxReleaseAmount()).to.equal(maxRelease);
      expect(await vault.dailyReleaseLimit()).to.equal(dailyLimit);
      expect(await vault.maxDepositAmount()).to.equal(maxDeposit);
      expect(await vault.dailyDepositLimit()).to.equal(dailyDepositLimit);
      expect(await vault.maxLockedAmount()).to.equal(maxLocked);
      expect(await vault.depositDay()).to.equal(0n);
      expect(await vault.depositedToday()).to.equal(0n);
    });

    it('rejects zero and inconsistent deposit limits', async function () {
      const invalid = [
        { maxDeposit: 0n },
        { dailyDepositLimit: 0n },
        { maxLocked: 0n },
        { maxDeposit: dailyDepositLimit + 1n },
        { maxDeposit: ethers.parseEther('60'), maxLocked: ethers.parseEther('59') }
      ];
      for (const overrides of invalid) {
        await expect(deployVault(overrides))
          .to.be.revertedWithCustomError(vault, 'InvalidDepositLimits');
      }
    });

    it('accepts equal per-deposit, daily and locked limits', async function () {
      const limit = ethers.parseEther('5');
      const equalLimits = await deployVault({
        maxDeposit: limit,
        dailyDepositLimit: limit,
        maxLocked: limit
      });
      expect(await equalLimits.maxDepositAmount()).to.equal(limit);
      expect(await equalLimits.dailyDepositLimit()).to.equal(limit);
      expect(await equalLimits.maxLockedAmount()).to.equal(limit);
    });

    it('rejects duplicate signers', async function () {
      const Vault = await ethers.getContractFactory('CronosBridgeVault');
      await expect(
        Vault.deploy(
          await token.getAddress(),
          routeId,
          [signerOne.address, signerOne.address, signerThree.address],
          guardian.address,
          maxRelease,
          dailyLimit,
          maxDeposit,
          dailyDepositLimit,
          maxLocked,
          false
        )
      ).to.be.revertedWithCustomError(vault, 'InvalidSignerSet');
    });

    it('rejects inconsistent limits', async function () {
      const Vault = await ethers.getContractFactory('CronosBridgeVault');
      await expect(
        Vault.deploy(
          await token.getAddress(),
          routeId,
          [signerOne.address, signerTwo.address, signerThree.address],
          guardian.address,
          dailyLimit + 1n,
          dailyLimit,
          maxDeposit,
          dailyDepositLimit,
          maxLocked,
          false
        )
      ).to.be.revertedWithCustomError(vault, 'InvalidAmount');
    });
  });

  describe('deposits', function () {
    it('locks the exact amount and emits a unique deposit identifier', async function () {
      const amount = ethers.parseEther('25');
      await token.connect(user).approve(await vault.getAddress(), amount);

      const transaction = vault.connect(user).deposit(amount, recipient.address);
      await expect(transaction)
        .to.emit(vault, 'Deposited')
        .withArgs(
          anyValue,
          routeId,
          user.address,
          recipient.address,
          amount,
          1n
        );

      expect(await vault.depositNonce()).to.equal(1n);
      expect(await token.balanceOf(await vault.getAddress())).to.equal(
        ethers.parseEther('525')
      );
    });

    it('rejects zero and dead recipients', async function () {
      const amount = ethers.parseEther('1');
      await token.connect(user).approve(await vault.getAddress(), amount * 2n);

      await expect(
        vault.connect(user).deposit(amount, ethers.ZeroAddress)
      ).to.be.revertedWithCustomError(vault, 'InvalidAddress');
      await expect(
        vault.connect(user).deposit(amount, deadAddress)
      ).to.be.revertedWithCustomError(vault, 'InvalidAddress');
    });
  });

  describe('releases', function () {
    it('releases XTC after two distinct signer approvals', async function () {
      const sourceBurnId = ethers.id('xitcoin-burn-1');
      const amount = ethers.parseEther('10');
      const { expiry, signatures } = await signRelease({
        sourceBurnId,
        amount
      });

      await expect(
        vault.release(
          sourceBurnId,
          recipient.address,
          amount,
          1,
          expiry,
          signatures
        )
      )
        .to.emit(vault, 'Released')
        .withArgs(sourceBurnId, recipient.address, amount, 1n);

      expect(await token.balanceOf(recipient.address)).to.equal(amount);
      expect(await vault.processedBurns(sourceBurnId)).to.equal(true);
    });

    it('rejects one signature, duplicates and non-signers', async function () {
      const sourceBurnId = ethers.id('xitcoin-burn-quorum');
      const amount = ethers.parseEther('5');

      const one = await signRelease({
        sourceBurnId,
        amount,
        signers: [signerOne]
      });
      await expect(
        vault.release(
          sourceBurnId,
          recipient.address,
          amount,
          1,
          one.expiry,
          one.signatures
        )
      ).to.be.revertedWithCustomError(vault, 'InsufficientSignatures');

      await expect(
        vault.release(
          sourceBurnId,
          recipient.address,
          amount,
          1,
          one.expiry,
          [one.signatures[0], one.signatures[0]]
        )
      ).to.be.revertedWithCustomError(vault, 'DuplicateSignature');

      const unauthorized = await signRelease({
        sourceBurnId,
        amount,
        signers: [signerOne, outsider]
      });
      await expect(
        vault.release(
          sourceBurnId,
          recipient.address,
          amount,
          1,
          unauthorized.expiry,
          unauthorized.signatures
        )
      ).to.be.revertedWithCustomError(vault, 'UnauthorizedSigner');
    });

    it('rejects replay, expired approvals and the wrong signer-set version', async function () {
      const sourceBurnId = ethers.id('xitcoin-burn-replay');
      const amount = ethers.parseEther('5');
      const signed = await signRelease({ sourceBurnId, amount });

      await vault.release(
        sourceBurnId,
        recipient.address,
        amount,
        1,
        signed.expiry,
        signed.signatures
      );
      await expect(
        vault.release(
          sourceBurnId,
          recipient.address,
          amount,
          1,
          signed.expiry,
          signed.signatures
        )
      ).to.be.revertedWithCustomError(vault, 'BurnAlreadyProcessed');

      const expiredId = ethers.id('xitcoin-burn-expired');
      const expired = await signRelease({
        sourceBurnId: expiredId,
        amount,
        expires: 1n
      });
      await expect(
        vault.release(
          expiredId,
          recipient.address,
          amount,
          1,
          expired.expiry,
          expired.signatures
        )
      ).to.be.revertedWithCustomError(vault, 'SignatureExpired');

      await expect(
        vault.release(
          ethers.id('wrong-version'),
          recipient.address,
          amount,
          2,
          signed.expiry,
          signed.signatures
        )
      ).to.be.revertedWithCustomError(vault, 'InvalidSignerSetVersion');
    });

    it('enforces per-release, daily and liquidity limits', async function () {
      const overMaximum = maxRelease + 1n;
      const overMaximumSigned = await signRelease({
        sourceBurnId: ethers.id('over-maximum'),
        amount: overMaximum
      });
      await expect(
        vault.release(
          ethers.id('over-maximum'),
          recipient.address,
          overMaximum,
          1,
          overMaximumSigned.expiry,
          overMaximumSigned.signatures
        )
      ).to.be.revertedWithCustomError(vault, 'ReleaseLimitExceeded');

      const firstId = ethers.id('daily-one');
      const first = await signRelease({
        sourceBurnId: firstId,
        amount: maxRelease
      });
      await vault.release(
        firstId,
        recipient.address,
        maxRelease,
        1,
        first.expiry,
        first.signatures
      );

      const secondAmount = ethers.parseEther('51');
      const secondId = ethers.id('daily-two');
      const second = await signRelease({
        sourceBurnId: secondId,
        amount: secondAmount
      });
      await expect(
        vault.release(
          secondId,
          recipient.address,
          secondAmount,
          1,
          second.expiry,
          second.signatures
        )
      ).to.be.revertedWithCustomError(vault, 'DailyLimitExceeded');
    });

    it('binds approvals to the vault address', async function () {
      const Vault = await ethers.getContractFactory('CronosBridgeVault');
      const secondVault = await Vault.deploy(
        await token.getAddress(),
        routeId,
        [signerOne.address, signerTwo.address, signerThree.address],
        guardian.address,
        maxRelease,
        dailyLimit,
        maxDeposit,
        dailyDepositLimit,
        maxLocked,
        false
      );
      await token.mint(await secondVault.getAddress(), ethers.parseEther('20'));

      const sourceBurnId = ethers.id('domain-bound');
      const amount = ethers.parseEther('1');
      const signedForFirstVault = await signRelease({ sourceBurnId, amount });

      await expect(
        secondVault.release(
          sourceBurnId,
          recipient.address,
          amount,
          1,
          signedForFirstVault.expiry,
          signedForFirstVault.signatures
        )
      ).to.be.revertedWithCustomError(secondVault, 'UnauthorizedSigner');
    });
  });

  describe('emergency and governance controls', function () {
    it('allows only the guardian to pause and requires quorum to resume', async function () {
      await expect(vault.connect(outsider).pause())
        .to.be.revertedWithCustomError(vault, 'UnauthorizedGuardian');

      await expect(vault.connect(guardian).pause())
        .to.emit(vault, 'VaultPaused')
        .withArgs(guardian.address);

      const resume = await signControl({ action: await vault.ACTION_RESUME() });
      await expect(
        vault.resume(resume.nonce, resume.expiry, resume.signatures)
      )
        .to.emit(vault, 'VaultResumed')
        .withArgs(0n);

      expect(await vault.paused()).to.equal(false);
      expect(await vault.governanceNonce()).to.equal(1n);
    });

    it('rotates the signer set and invalidates old approvals', async function () {
      const newSigners = [
        replacementOne.address,
        replacementTwo.address,
        replacementThree.address
      ];
      const payloadHash = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ['address[3]'],
          [newSigners]
        )
      );
      const rotation = await signControl({
        action: await vault.ACTION_ROTATE_SIGNERS(),
        payloadHash
      });

      await vault.rotateSigners(
        newSigners,
        rotation.nonce,
        rotation.expiry,
        rotation.signatures
      );

      expect(await vault.signerSetVersion()).to.equal(2n);
      expect(await vault.isSigner(signerOne.address)).to.equal(false);
      expect(await vault.isSigner(replacementOne.address)).to.equal(true);

      const sourceBurnId = ethers.id('post-rotation');
      const amount = ethers.parseEther('1');
      const oldSigners = await signRelease({
        sourceBurnId,
        amount,
        version: 2n,
        signers: [signerOne, signerTwo]
      });
      await expect(
        vault.release(
          sourceBurnId,
          recipient.address,
          amount,
          2,
          oldSigners.expiry,
          oldSigners.signatures
        )
      ).to.be.revertedWithCustomError(vault, 'UnauthorizedSigner');

      const newApprovals = await signRelease({
        sourceBurnId,
        amount,
        version: 2n,
        signers: [replacementOne, replacementTwo]
      });
      await vault.release(
        sourceBurnId,
        recipient.address,
        amount,
        2,
        newApprovals.expiry,
        newApprovals.signatures
      );
    });

    it('updates release limits only after a valid quorum action', async function () {
      const newMaximum = ethers.parseEther('200');
      const newDaily = ethers.parseEther('500');
      const payloadHash = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ['uint256', 'uint256'],
          [newMaximum, newDaily]
        )
      );
      const control = await signControl({
        action: await vault.ACTION_UPDATE_LIMITS(),
        payloadHash
      });

      await vault.updateLimits(
        newMaximum,
        newDaily,
        control.nonce,
        control.expiry,
        control.signatures
      );

      expect(await vault.maxReleaseAmount()).to.equal(newMaximum);
      expect(await vault.dailyReleaseLimit()).to.equal(newDaily);
    });

    it('rejects governance nonce replay', async function () {
      await vault.connect(guardian).pause();
      const resume = await signControl({ action: await vault.ACTION_RESUME() });
      await vault.resume(resume.nonce, resume.expiry, resume.signatures);
      await vault.connect(guardian).pause();

      await expect(
        vault.resume(resume.nonce, resume.expiry, resume.signatures)
      ).to.be.revertedWithCustomError(vault, 'InvalidNonce');
    });
  });

  describe('deposit limits', function () {
    it('accepts exactly the per-deposit maximum and rejects one unit more', async function () {
      await token.connect(user).approve(await vault.getAddress(), maxDeposit + 1n);
      await expect(
        vault.connect(user).deposit(maxDeposit + 1n, recipient.address)
      ).to.be.revertedWithCustomError(vault, 'DepositLimitExceeded');
      expect(await vault.depositNonce()).to.equal(0n);

      await expect(vault.connect(user).deposit(maxDeposit, recipient.address))
        .to.emit(vault, 'Deposited');
      expect(await vault.depositedToday()).to.equal(maxDeposit);
    });

    it('enforces the daily deposit limit and resets it at the next UTC day', async function () {
      const day = 86400n;
      const today = (await latestTimestamp()) / day + 1n;
      const dayStart = today * day;

      await nextTimestamp(dayStart);
      await approveAndDeposit(maxDeposit);
      await approveAndDeposit(maxDeposit);
      const remaining = dailyDepositLimit - 2n * maxDeposit;

      await token.connect(user).approve(await vault.getAddress(), remaining + 1n);
      await expect(
        vault.connect(user).deposit(remaining + 1n, recipient.address)
      ).to.be.revertedWithCustomError(vault, 'DailyDepositLimitExceeded');
      expect(await vault.depositedToday()).to.equal(2n * maxDeposit);
      expect(await vault.depositNonce()).to.equal(2n);

      await vault.connect(user).deposit(remaining, recipient.address);
      expect(await vault.depositedToday()).to.equal(dailyDepositLimit);
      expect(await vault.depositDay()).to.equal(today);

      // Last second of the same UTC day: still the same bucket.
      await token.connect(user).approve(await vault.getAddress(), 1n);
      await nextTimestamp(dayStart + day - 1n);
      await expect(
        vault.connect(user).deposit(1n, recipient.address, { gasLimit: 500000 })
      ).to.be.revertedWithCustomError(vault, 'DailyDepositLimitExceeded');

      // First second of the next UTC day: a new bucket.
      await nextTimestamp(dayStart + day);
      await vault.connect(user).deposit(1n, recipient.address, { gasLimit: 500000 });
      expect(await vault.depositDay()).to.equal(today + 1n);
      expect(await vault.depositedToday()).to.equal(1n);
    });

    it('counts direct donations toward the locked cap', async function () {
      const vaultAddress = await vault.getAddress();
      // 500 seeded + 150 donated = 650; the cap is 700.
      await token.mint(outsider.address, ethers.parseEther('150'));
      await token.connect(outsider).transfer(vaultAddress, ethers.parseEther('150'));

      await token.connect(user).approve(vaultAddress, maxDeposit + 1n);
      await expect(vault.connect(user).deposit(maxDeposit, recipient.address))
        .to.emit(vault, 'Deposited');
      expect(await token.balanceOf(vaultAddress)).to.equal(maxLocked);

      await expect(
        vault.connect(user).deposit(1n, recipient.address)
      ).to.be.revertedWithCustomError(vault, 'LockedAmountCapExceeded');
      expect(await vault.depositedToday()).to.equal(maxDeposit);
      expect(await vault.depositNonce()).to.equal(1n);
    });

    it('rejects every deposit while donations keep the balance above the cap', async function () {
      const vaultAddress = await vault.getAddress();
      await token.mint(vaultAddress, ethers.parseEther('300'));
      expect(await token.balanceOf(vaultAddress)).to.be.greaterThan(maxLocked);

      await token.connect(user).approve(vaultAddress, 1n);
      await expect(
        vault.connect(user).deposit(1n, recipient.address)
      ).to.be.revertedWithCustomError(vault, 'LockedAmountCapExceeded');

      // Releases reduce the balance and reopen deposit capacity.
      await releaseSigned(ethers.id('cap-release-one'), maxRelease);
      await releaseSigned(ethers.id('cap-release-two'), ethers.parseEther('10'));
      expect(await token.balanceOf(vaultAddress)).to.equal(ethers.parseEther('690'));
      await vault.connect(user).deposit(1n, recipient.address);
    });

    it('rejects deposits while paused without touching accounting', async function () {
      await vault.connect(guardian).pause();
      await token.connect(user).approve(await vault.getAddress(), 1n);
      await expect(
        vault.connect(user).deposit(1n, recipient.address)
      ).to.be.revertedWithCustomError(vault, 'EnforcedPause');
      expect(await vault.depositedToday()).to.equal(0n);
      expect(await vault.depositNonce()).to.equal(0n);
    });
  });

  describe('deposit limit governance', function () {
    const newMaximum = ethers.parseEther('80');
    const newDaily = ethers.parseEther('200');
    const newLocked = ethers.parseEther('900');

    it('updates deposit limits only after a valid quorum action', async function () {
      const action = await vault.ACTION_UPDATE_DEPOSIT_LIMITS();
      expect(action).to.equal(ethers.id('UPDATE_DEPOSIT_LIMITS'));
      const control = await signControl({
        action,
        payloadHash: depositLimitsPayload(newMaximum, newDaily, newLocked)
      });

      await expect(
        vault.connect(outsider).updateDepositLimits(
          newMaximum,
          newDaily,
          newLocked,
          control.nonce,
          control.expiry,
          control.signatures
        )
      )
        .to.emit(vault, 'DepositLimitsUpdated')
        .withArgs(newMaximum, newDaily, newLocked, 0n);

      expect(await vault.maxDepositAmount()).to.equal(newMaximum);
      expect(await vault.dailyDepositLimit()).to.equal(newDaily);
      expect(await vault.maxLockedAmount()).to.equal(newLocked);
      expect(await vault.governanceNonce()).to.equal(1n);
      // Release limits are independent.
      expect(await vault.maxReleaseAmount()).to.equal(maxRelease);
      expect(await vault.dailyReleaseLimit()).to.equal(dailyLimit);

      await token.connect(user).approve(await vault.getAddress(), newMaximum);
      await vault.connect(user).deposit(newMaximum, recipient.address);
      expect(await vault.depositedToday()).to.equal(newMaximum);

      await expect(
        vault.updateDepositLimits(
          newMaximum,
          newDaily,
          newLocked,
          control.nonce,
          control.expiry,
          control.signatures
        )
      ).to.be.revertedWithCustomError(vault, 'InvalidNonce');
    });

    it('rejects insufficient, duplicate, outsider and expired approvals', async function () {
      const action = await vault.ACTION_UPDATE_DEPOSIT_LIMITS();
      const payloadHash = depositLimitsPayload(newMaximum, newDaily, newLocked);

      const one = await signControl({ action, payloadHash, signers: [signerOne] });
      await expect(
        vault.updateDepositLimits(newMaximum, newDaily, newLocked, one.nonce, one.expiry, one.signatures)
      ).to.be.revertedWithCustomError(vault, 'InsufficientSignatures');
      await expect(
        vault.updateDepositLimits(
          newMaximum,
          newDaily,
          newLocked,
          one.nonce,
          one.expiry,
          [one.signatures[0], one.signatures[0]]
        )
      ).to.be.revertedWithCustomError(vault, 'DuplicateSignature');

      const outsiderApproval = await signControl({
        action,
        payloadHash,
        signers: [signerOne, outsider]
      });
      await expect(
        vault.updateDepositLimits(
          newMaximum,
          newDaily,
          newLocked,
          outsiderApproval.nonce,
          outsiderApproval.expiry,
          outsiderApproval.signatures
        )
      ).to.be.revertedWithCustomError(vault, 'UnauthorizedSigner');

      const expired = await signControl({ action, payloadHash, expires: 1n });
      await expect(
        vault.updateDepositLimits(
          newMaximum,
          newDaily,
          newLocked,
          expired.nonce,
          expired.expiry,
          expired.signatures
        )
      ).to.be.revertedWithCustomError(vault, 'SignatureExpired');

      expect(await vault.governanceNonce()).to.equal(0n);
      expect(await vault.maxDepositAmount()).to.equal(maxDeposit);
    });

    it('binds approval to every limit value and to the action', async function () {
      const action = await vault.ACTION_UPDATE_DEPOSIT_LIMITS();
      const control = await signControl({
        action,
        payloadHash: depositLimitsPayload(newMaximum, newDaily, newLocked)
      });
      const mutations = [
        [newMaximum + 1n, newDaily, newLocked],
        [newMaximum, newDaily + 1n, newLocked],
        [newMaximum, newDaily, newLocked + 1n]
      ];
      for (const [maximum, daily, locked] of mutations) {
        await expect(
          vault.updateDepositLimits(maximum, daily, locked, control.nonce, control.expiry, control.signatures)
        ).to.be.revertedWithCustomError(vault, 'UnauthorizedSigner');
      }

      // A release-limit approval over the same payload hash is not reusable.
      const otherAction = await signControl({
        action: await vault.ACTION_UPDATE_LIMITS(),
        payloadHash: depositLimitsPayload(newMaximum, newDaily, newLocked)
      });
      await expect(
        vault.updateDepositLimits(
          newMaximum,
          newDaily,
          newLocked,
          otherAction.nonce,
          otherAction.expiry,
          otherAction.signatures
        )
      ).to.be.revertedWithCustomError(vault, 'UnauthorizedSigner');
      expect(await vault.governanceNonce()).to.equal(0n);
    });

    it('rejects invalid limit values without consuming the nonce', async function () {
      const action = await vault.ACTION_UPDATE_DEPOSIT_LIMITS();
      const invalid = [
        [0n, newDaily, newLocked],
        [newMaximum, 0n, newLocked],
        [newMaximum, newDaily, 0n],
        [newDaily + 1n, newDaily, newLocked],
        [newMaximum, newDaily, newMaximum - 1n]
      ];
      for (const [maximum, daily, locked] of invalid) {
        const control = await signControl({
          action,
          payloadHash: depositLimitsPayload(maximum, daily, locked)
        });
        await expect(
          vault.updateDepositLimits(maximum, daily, locked, control.nonce, control.expiry, control.signatures)
        ).to.be.revertedWithCustomError(vault, 'InvalidDepositLimits');
      }
      expect(await vault.governanceNonce()).to.equal(0n);
    });

    it('rejects approvals from a rotated-out signer set', async function () {
      const action = await vault.ACTION_UPDATE_DEPOSIT_LIMITS();
      const payloadHash = depositLimitsPayload(newMaximum, newDaily, newLocked);
      const staleApproval = await signControl({ action, payloadHash, nonce: 1n, version: 1n });

      const newSigners = [replacementOne.address, replacementTwo.address, replacementThree.address];
      const rotation = await signControl({
        action: await vault.ACTION_ROTATE_SIGNERS(),
        payloadHash: ethers.keccak256(
          ethers.AbiCoder.defaultAbiCoder().encode(['address[3]'], [newSigners])
        )
      });
      await vault.rotateSigners(newSigners, rotation.nonce, rotation.expiry, rotation.signatures);

      await expect(
        vault.updateDepositLimits(
          newMaximum,
          newDaily,
          newLocked,
          staleApproval.nonce,
          staleApproval.expiry,
          staleApproval.signatures
        )
      ).to.be.revertedWithCustomError(vault, 'UnauthorizedSigner');

      const freshApproval = await signControl({
        action,
        payloadHash,
        signers: [replacementOne, replacementThree]
      });
      await vault.updateDepositLimits(
        newMaximum,
        newDaily,
        newLocked,
        freshApproval.nonce,
        freshApproval.expiry,
        freshApproval.signatures
      );
      expect(await vault.maxLockedAmount()).to.equal(newLocked);
      expect(await vault.governanceNonce()).to.equal(2n);
    });

    it('keeps the day total and lets a cap below the balance stop deposits only', async function () {
      await approveAndDeposit(ethers.parseEther('40'));
      const loweredMaximum = ethers.parseEther('10');
      const loweredDaily = ethers.parseEther('45');
      const loweredLocked = ethers.parseEther('100');
      const control = await signControl({
        action: await vault.ACTION_UPDATE_DEPOSIT_LIMITS(),
        payloadHash: depositLimitsPayload(loweredMaximum, loweredDaily, loweredLocked)
      });
      await vault.updateDepositLimits(
        loweredMaximum,
        loweredDaily,
        loweredLocked,
        control.nonce,
        control.expiry,
        control.signatures
      );
      expect(await vault.depositedToday()).to.equal(ethers.parseEther('40'));

      await token.connect(user).approve(await vault.getAddress(), 1n);
      await expect(
        vault.connect(user).deposit(1n, recipient.address)
      ).to.be.revertedWithCustomError(vault, 'LockedAmountCapExceeded');

      // Releases are not affected by deposit limits.
      await releaseSigned(ethers.id('after-lowered-cap'), ethers.parseEther('10'));
      expect(await token.balanceOf(recipient.address)).to.equal(ethers.parseEther('10'));
    });
  });

  describe('asset isolation', function () {
    it('forbids rescue of canonical XTC', async function () {
      await expect(
        vault.rescueForeignToken(
          await token.getAddress(),
          recipient.address,
          1,
          0,
          await deadline(),
          []
        )
      ).to.be.revertedWithCustomError(
        vault,
        'CanonicalAssetRescueForbidden'
      );
    });

    it('recovers only unrelated tokens after quorum approval', async function () {
      const Token = await ethers.getContractFactory('MockERC20');
      const foreignToken = await Token.deploy('Foreign', 'FRN');
      const amount = ethers.parseEther('7');
      await foreignToken.mint(await vault.getAddress(), amount);

      const payloadHash = ethers.keccak256(
        ethers.AbiCoder.defaultAbiCoder().encode(
          ['address', 'address', 'uint256'],
          [await foreignToken.getAddress(), recipient.address, amount]
        )
      );
      const control = await signControl({
        action: await vault.ACTION_RESCUE_FOREIGN_TOKEN(),
        payloadHash
      });

      await vault.rescueForeignToken(
        await foreignToken.getAddress(),
        recipient.address,
        amount,
        control.nonce,
        control.expiry,
        control.signatures
      );

      expect(await foreignToken.balanceOf(recipient.address)).to.equal(amount);
      expect(await token.balanceOf(await vault.getAddress())).to.equal(
        ethers.parseEther('500')
      );
    });
  });
});
