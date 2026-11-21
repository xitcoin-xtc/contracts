import { expect } from 'chai';
import { network } from 'hardhat';

const { ethers } = await network.create();

describe('CronosBootstrapEscrow', function () {
  const genesisHash = ethers.sha256(ethers.toUtf8Bytes('canonical-mainnet-genesis'));
  const expectedAmount = ethers.parseEther('20000100');

  let fundingAccount;
  let refundRecipient;
  let permanentVault;
  let signerOne;
  let signerTwo;
  let signerThree;
  let outsider;
  let token;
  let escrow;

  async function deadline(offset = 3600n) {
    const block = await ethers.provider.getBlock('latest');
    return BigInt(block.timestamp) + offset;
  }

  async function decisionSignatures(action, options = {}) {
    const network = await ethers.provider.getNetwork();
    const nonce = options.nonce ?? await escrow.decisionNonce();
    const expiry = options.expiry ?? await deadline();
    const signers = options.signers ?? [signerOne, signerTwo];
    const domain = {
      name: 'Xitcoin Cronos Bootstrap Escrow',
      version: '1',
      chainId: network.chainId,
      verifyingContract: await escrow.getAddress()
    };
    const types = {
      Decision: [
        { name: 'action', type: 'bytes32' },
        { name: 'genesisHash', type: 'bytes32' },
        { name: 'expectedAmount', type: 'uint256' },
        { name: 'nonce', type: 'uint256' },
        { name: 'deadline', type: 'uint256' }
      ]
    };
    const value = {
      action,
      genesisHash,
      expectedAmount,
      nonce,
      deadline: expiry
    };
    const signatures = [];
    for (const signer of signers) {
      signatures.push(await signer.signTypedData(domain, types, value));
    }
    return { nonce, expiry, signatures };
  }

  beforeEach(async function () {
    [
      fundingAccount,
      refundRecipient,
      permanentVault,
      signerOne,
      signerTwo,
      signerThree,
      outsider
    ] = await ethers.getSigners();

    const Token = await ethers.getContractFactory('MockERC20');
    token = await Token.deploy('Xitcoin', '$XTC');

    const Escrow = await ethers.getContractFactory('CronosBootstrapEscrow');
    escrow = await Escrow.deploy(
      await token.getAddress(),
      permanentVault.address,
      refundRecipient.address,
      fundingAccount.address,
      genesisHash,
      expectedAmount,
      [signerOne.address, signerTwo.address, signerThree.address]
    );

    await token.mint(fundingAccount.address, expectedAmount);
    await token.connect(fundingAccount).approve(await escrow.getAddress(), expectedAmount);
  });

  async function fund() {
    await expect(escrow.connect(fundingAccount).fund())
      .to.emit(escrow, 'BootstrapFunded')
      .withArgs(fundingAccount.address, expectedAmount);
  }

  async function nextTimestamp(timestamp) {
    await ethers.provider.send('evm_setNextBlockTimestamp', [Number(timestamp)]);
  }

  // Explicit gas avoids estimating against a block other than the one mined.
  const mined = { gasLimit: 1000000 };

  it('accepts the exact reserve only from the fixed funding account', async function () {
    await expect(escrow.connect(outsider).fund())
      .to.be.revertedWithCustomError(escrow, 'UnauthorizedFunder');
    await fund();
    expect(await escrow.state()).to.equal(1n);
    expect(await token.balanceOf(await escrow.getAddress())).to.equal(expectedAmount);
    await expect(escrow.connect(fundingAccount).fund())
      .to.be.revertedWithCustomError(escrow, 'InvalidState');
  });

  it('activates once with 2-of-3 approval and sends all backing to the fixed vault', async function () {
    await fund();
    const dust = 7n;
    await token.mint(outsider.address, dust);
    await token.connect(outsider).transfer(await escrow.getAddress(), dust);

    const action = await escrow.ACTION_ACTIVATE();
    const approval = await decisionSignatures(action);
    await expect(escrow.activate(approval.nonce, approval.expiry, approval.signatures))
      .to.emit(escrow, 'BootstrapActivated')
      .withArgs(permanentVault.address, expectedAmount + dust, genesisHash);

    expect(await escrow.state()).to.equal(2n);
    expect(await token.balanceOf(permanentVault.address)).to.equal(expectedAmount + dust);
    expect(await token.balanceOf(await escrow.getAddress())).to.equal(0n);

    const cancellation = await decisionSignatures(await escrow.ACTION_CANCEL());
    await expect(escrow.cancel(cancellation.nonce, cancellation.expiry, cancellation.signatures))
      .to.be.revertedWithCustomError(escrow, 'InvalidState');
  });

  it('cancels once with 2-of-3 approval and refunds only the fixed recipient', async function () {
    await fund();
    const action = await escrow.ACTION_CANCEL();
    const approval = await decisionSignatures(action);
    await expect(escrow.cancel(approval.nonce, approval.expiry, approval.signatures))
      .to.emit(escrow, 'BootstrapCancelled')
      .withArgs(refundRecipient.address, expectedAmount, genesisHash);

    expect(await escrow.state()).to.equal(3n);
    expect(await token.balanceOf(refundRecipient.address)).to.equal(expectedAmount);
    expect(await token.balanceOf(permanentVault.address)).to.equal(0n);
  });

  it('forwards late direct transfers only to the activated permanent vault', async function () {
    await fund();
    const approval = await decisionSignatures(await escrow.ACTION_ACTIVATE());
    await escrow.activate(approval.nonce, approval.expiry, approval.signatures);

    const lateAmount = ethers.parseEther('3');
    await token.mint(outsider.address, lateAmount);
    await token.connect(outsider).transfer(await escrow.getAddress(), lateAmount);

    await expect(escrow.connect(outsider).forwardTerminalBalance())
      .to.emit(escrow, 'TerminalBalanceForwarded')
      .withArgs(permanentVault.address, lateAmount, 2n);
    expect(await token.balanceOf(permanentVault.address)).to.equal(
      expectedAmount + lateAmount
    );
  });

  it('forwards late direct transfers only to the fixed refund recipient after cancellation', async function () {
    await fund();
    const approval = await decisionSignatures(await escrow.ACTION_CANCEL());
    await escrow.cancel(approval.nonce, approval.expiry, approval.signatures);

    const lateAmount = ethers.parseEther('3');
    await token.mint(outsider.address, lateAmount);
    await token.connect(outsider).transfer(await escrow.getAddress(), lateAmount);

    await expect(escrow.connect(outsider).forwardTerminalBalance())
      .to.emit(escrow, 'TerminalBalanceForwarded')
      .withArgs(refundRecipient.address, lateAmount, 3n);
    expect(await token.balanceOf(refundRecipient.address)).to.equal(
      expectedAmount + lateAmount
    );
  });

  it('cannot forward a balance before a terminal decision', async function () {
    await expect(escrow.forwardTerminalBalance())
      .to.be.revertedWithCustomError(escrow, 'InvalidState');
  });

  it('rejects one signer, duplicate signatures and outsiders', async function () {
    await fund();
    const action = await escrow.ACTION_ACTIVATE();

    const one = await decisionSignatures(action, { signers: [signerOne] });
    await expect(escrow.activate(one.nonce, one.expiry, one.signatures))
      .to.be.revertedWithCustomError(escrow, 'InsufficientSignatures');

    const duplicate = await decisionSignatures(action, { signers: [signerOne, signerOne] });
    await expect(escrow.activate(duplicate.nonce, duplicate.expiry, duplicate.signatures))
      .to.be.revertedWithCustomError(escrow, 'DuplicateSignature');

    const unauthorized = await decisionSignatures(action, { signers: [signerOne, outsider] });
    await expect(escrow.activate(unauthorized.nonce, unauthorized.expiry, unauthorized.signatures))
      .to.be.revertedWithCustomError(escrow, 'UnauthorizedSigner');
  });

  it('binds approval to the action and rejects expired decisions', async function () {
    await fund();
    const cancellation = await decisionSignatures(await escrow.ACTION_CANCEL());
    await expect(
      escrow.activate(cancellation.nonce, cancellation.expiry, cancellation.signatures)
    ).to.be.revertedWithCustomError(escrow, 'UnauthorizedSigner');

    const expired = await decisionSignatures(await escrow.ACTION_ACTIVATE(), { expiry: 1n });
    await expect(escrow.activate(expired.nonce, expired.expiry, expired.signatures))
      .to.be.revertedWithCustomError(escrow, 'SignatureExpired');
  });

  describe('timeout refund', function () {
    let timeout;
    let fundedAt;

    beforeEach(async function () {
      timeout = await escrow.REFUND_TIMEOUT();
      expect(await escrow.fundedAt()).to.equal(0n);
      expect(await escrow.refundAvailableAt()).to.equal(0n);
      await fund();
      fundedAt = await escrow.fundedAt();
    });

    async function longLivedDecision(action) {
      return decisionSignatures(action, { expiry: fundedAt + timeout + 86400n });
    }

    it('uses a fixed 180-day delay from the recorded funding time', async function () {
      const block = await ethers.provider.getBlock('latest');
      expect(timeout).to.equal(180n * 86400n);
      expect(fundedAt).to.equal(BigInt(block.timestamp));
      expect(await escrow.refundAvailableAt()).to.equal(fundedAt + timeout);
    });

    it('cannot refund before funding', async function () {
      const Escrow = await ethers.getContractFactory('CronosBootstrapEscrow');
      const unfunded = await Escrow.deploy(
        await token.getAddress(),
        permanentVault.address,
        refundRecipient.address,
        fundingAccount.address,
        genesisHash,
        expectedAmount,
        [signerOne.address, signerTwo.address, signerThree.address]
      );
      await expect(unfunded.refundAfterTimeout())
        .to.be.revertedWithCustomError(unfunded, 'InvalidState');
    });

    it('rejects a refund one second before the timeout', async function () {
      await nextTimestamp(fundedAt + timeout - 1n);
      await expect(escrow.connect(outsider).refundAfterTimeout(mined))
        .to.be.revertedWithCustomError(escrow, 'RefundTimeoutNotReached');
      expect(await escrow.state()).to.equal(1n);
      expect(await token.balanceOf(await escrow.getAddress())).to.equal(expectedAmount);
    });

    it('still allows activation one second before the timeout', async function () {
      const approval = await longLivedDecision(await escrow.ACTION_ACTIVATE());
      await nextTimestamp(fundedAt + timeout - 1n);
      await escrow.activate(approval.nonce, approval.expiry, approval.signatures, mined);
      expect(await escrow.state()).to.equal(2n);
      await expect(escrow.refundAfterTimeout())
        .to.be.revertedWithCustomError(escrow, 'InvalidState');
    });

    it('still allows cancellation one second before the timeout', async function () {
      const approval = await longLivedDecision(await escrow.ACTION_CANCEL());
      await nextTimestamp(fundedAt + timeout - 1n);
      await escrow.cancel(approval.nonce, approval.expiry, approval.signatures, mined);
      expect(await escrow.state()).to.equal(3n);
      await expect(escrow.refundAfterTimeout())
        .to.be.revertedWithCustomError(escrow, 'InvalidState');
    });

    it('lets anyone refund the whole balance to the fixed recipient at the timeout', async function () {
      const dust = 11n;
      await token.mint(outsider.address, dust);
      await token.connect(outsider).transfer(await escrow.getAddress(), dust);

      await nextTimestamp(fundedAt + timeout);
      await expect(escrow.connect(outsider).refundAfterTimeout(mined))
        .to.emit(escrow, 'BootstrapRefundedAfterTimeout')
        .withArgs(refundRecipient.address, expectedAmount + dust, genesisHash, outsider.address);

      expect(await escrow.state()).to.equal(3n);
      expect(await token.balanceOf(refundRecipient.address)).to.equal(expectedAmount + dust);
      expect(await token.balanceOf(permanentVault.address)).to.equal(0n);
      expect(await token.balanceOf(await escrow.getAddress())).to.equal(0n);
      expect(await token.balanceOf(outsider.address)).to.equal(0n);

      await expect(escrow.refundAfterTimeout())
        .to.be.revertedWithCustomError(escrow, 'InvalidState');
    });

    it('rejects activation and cancellation once the timeout has elapsed', async function () {
      const activation = await longLivedDecision(await escrow.ACTION_ACTIVATE());
      await nextTimestamp(fundedAt + timeout);
      await expect(
        escrow.activate(activation.nonce, activation.expiry, activation.signatures, mined)
      ).to.be.revertedWithCustomError(escrow, 'RefundTimeoutElapsed');

      const cancellation = await longLivedDecision(await escrow.ACTION_CANCEL());
      await expect(
        escrow.cancel(cancellation.nonce, cancellation.expiry, cancellation.signatures)
      ).to.be.revertedWithCustomError(escrow, 'RefundTimeoutElapsed');

      expect(await escrow.state()).to.equal(1n);
      expect(await escrow.decisionNonce()).to.equal(0n);
      expect(await token.balanceOf(await escrow.getAddress())).to.equal(expectedAmount);
    });

    it('rejects activation and cancellation after a timeout refund', async function () {
      const activation = await longLivedDecision(await escrow.ACTION_ACTIVATE());
      const cancellation = await longLivedDecision(await escrow.ACTION_CANCEL());
      await nextTimestamp(fundedAt + timeout);
      await escrow.refundAfterTimeout(mined);

      await expect(
        escrow.activate(activation.nonce, activation.expiry, activation.signatures)
      ).to.be.revertedWithCustomError(escrow, 'InvalidState');
      await expect(
        escrow.cancel(cancellation.nonce, cancellation.expiry, cancellation.signatures)
      ).to.be.revertedWithCustomError(escrow, 'InvalidState');
      expect(await token.balanceOf(permanentVault.address)).to.equal(0n);
    });

    it('cannot refund after activation, even after the timeout', async function () {
      const approval = await decisionSignatures(await escrow.ACTION_ACTIVATE());
      await escrow.activate(approval.nonce, approval.expiry, approval.signatures);
      await nextTimestamp(fundedAt + timeout + 1n);
      await expect(escrow.refundAfterTimeout(mined))
        .to.be.revertedWithCustomError(escrow, 'InvalidState');
      expect(await token.balanceOf(permanentVault.address)).to.equal(expectedAmount);
      expect(await token.balanceOf(refundRecipient.address)).to.equal(0n);
    });

    it('cannot refund a second time after cancellation, even after the timeout', async function () {
      const approval = await decisionSignatures(await escrow.ACTION_CANCEL());
      await escrow.cancel(approval.nonce, approval.expiry, approval.signatures);
      await nextTimestamp(fundedAt + timeout + 1n);
      await expect(escrow.refundAfterTimeout(mined))
        .to.be.revertedWithCustomError(escrow, 'InvalidState');
      expect(await token.balanceOf(refundRecipient.address)).to.equal(expectedAmount);
    });

    it('forwards later direct transfers to the refund recipient after a timeout refund', async function () {
      await nextTimestamp(fundedAt + timeout);
      await escrow.refundAfterTimeout(mined);

      const lateAmount = ethers.parseEther('2');
      await token.mint(outsider.address, lateAmount);
      await token.connect(outsider).transfer(await escrow.getAddress(), lateAmount);

      await expect(escrow.connect(outsider).forwardTerminalBalance())
        .to.emit(escrow, 'TerminalBalanceForwarded')
        .withArgs(refundRecipient.address, lateAmount, 3n);
      expect(await token.balanceOf(refundRecipient.address)).to.equal(expectedAmount + lateAmount);
      expect(await token.balanceOf(permanentVault.address)).to.equal(0n);
    });
  });

  describe('timeout refund with a nonstandard token', function () {
    let adversarial;
    let guarded;

    beforeEach(async function () {
      const Adversarial = await ethers.getContractFactory('AdversarialERC20');
      adversarial = await Adversarial.deploy();
      const Escrow = await ethers.getContractFactory('CronosBootstrapEscrow');
      guarded = await Escrow.deploy(
        await adversarial.getAddress(),
        permanentVault.address,
        refundRecipient.address,
        fundingAccount.address,
        genesisHash,
        expectedAmount,
        [signerOne.address, signerTwo.address, signerThree.address]
      );
      await adversarial.mint(fundingAccount.address, expectedAmount);
      await adversarial.connect(fundingAccount).approve(await guarded.getAddress(), expectedAmount);
      await guarded.connect(fundingAccount).fund();
      const fundedAt = await guarded.fundedAt();
      await ethers.provider.send('evm_setNextBlockTimestamp', [
        Number(fundedAt + await guarded.REFUND_TIMEOUT())
      ]);
      await ethers.provider.send('evm_mine', []);
    });

    it('blocks reentry from a token callback', async function () {
      const reenter = guarded.interface.encodeFunctionData('refundAfterTimeout');
      await adversarial.configure(3, await guarded.getAddress(), reenter);
      await guarded.refundAfterTimeout();
      expect(await adversarial.callbackSucceeded()).to.equal(false);
      expect(await guarded.state()).to.equal(3n);
      expect(await adversarial.balanceOf(refundRecipient.address)).to.equal(expectedAmount);
    });

    it('rolls back the state change when the token transfer fails', async function () {
      await adversarial.configure(4, ethers.ZeroAddress, '0x');
      await expect(guarded.refundAfterTimeout()).to.be.revertedWithCustomError(
        guarded,
        'SafeERC20FailedOperation'
      );
      expect(await guarded.state()).to.equal(1n);
      expect(await adversarial.balanceOf(await guarded.getAddress())).to.equal(expectedAmount);
    });
  });

  it('cannot decide before the complete reserve is funded', async function () {
    const action = await escrow.ACTION_ACTIVATE();
    const approval = await decisionSignatures(action);
    await expect(escrow.activate(approval.nonce, approval.expiry, approval.signatures))
      .to.be.revertedWithCustomError(escrow, 'InvalidState');
  });
});
