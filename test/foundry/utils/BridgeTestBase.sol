// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import {CronosBridgeVault} from "../../../contracts/cronos/bridge/CronosBridgeVault.sol";
import {CronosBootstrapEscrow} from "../../../contracts/cronos/bridge/CronosBootstrapEscrow.sol";

// Local EVM simulations only. Every private key used here is a small public
// synthetic test key; no RPC, network or deployed contract is involved.

/// Cheatcodes provided by the Hardhat 3 (EDR) and Foundry test runners.
interface BridgeVm {
    function addr(uint256 privateKey) external returns (address);
    function sign(uint256 privateKey, bytes32 digest) external returns (uint8 v, bytes32 r, bytes32 s);
    function warp(uint256 timestamp) external;
    function chainId(uint256 newChainId) external;
    function prank(address sender) external;
}

/// Signing, encoding and bounding helpers shared by the bridge test suites.
abstract contract BridgeTestBase {
    BridgeVm internal constant vm =
        BridgeVm(address(uint160(uint256(keccak256("hevm cheat code")))));

    uint256 internal constant FAR_DEADLINE = 4_000_000_000;
    /// secp256k1 group order.
    uint256 internal constant SECP256K1_N =
        0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141;
    bytes32 internal constant EIP712_DOMAIN_TYPEHASH = keccak256(
        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
    );

    function _bound(uint256 x, uint256 min, uint256 max) internal pure returns (uint256) {
        if (max <= min) return min;
        return min + (x % (max - min + 1));
    }

    // ------------------------------------------------------------------
    // EIP-712
    // ------------------------------------------------------------------

    function _domain(
        string memory name,
        string memory version,
        uint256 chainId,
        address verifyingContract
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                EIP712_DOMAIN_TYPEHASH,
                keccak256(bytes(name)),
                keccak256(bytes(version)),
                chainId,
                verifyingContract
            )
        );
    }

    function _vaultDomain(CronosBridgeVault vault) internal view returns (bytes32) {
        return _domain(vault.EIP712_NAME(), vault.EIP712_VERSION(), block.chainid, address(vault));
    }

    function _escrowDomain(CronosBootstrapEscrow escrow) internal view returns (bytes32) {
        return _domain(escrow.EIP712_NAME(), escrow.EIP712_VERSION(), block.chainid, address(escrow));
    }

    function _typedDigest(bytes32 domainSeparator, bytes32 structHash) internal pure returns (bytes32) {
        return keccak256(abi.encodePacked("\x19\x01", domainSeparator, structHash));
    }

    function _releaseStruct(
        bytes32 burn,
        address recipient,
        uint256 amount,
        uint64 signerSetVersion,
        uint256 deadline
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256(
                    "Release(bytes32 sourceBurnId,address recipient,uint256 amount,uint64 signerSetVersion,uint256 deadline)"
                ),
                burn,
                recipient,
                amount,
                signerSetVersion,
                deadline
            )
        );
    }

    function _controlStruct(
        bytes32 action,
        bytes32 payloadHash,
        uint256 nonce,
        uint64 signerSetVersion,
        uint256 deadline
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256(
                    "Control(bytes32 action,bytes32 payloadHash,uint256 nonce,uint64 signerSetVersion,uint256 deadline)"
                ),
                action,
                payloadHash,
                nonce,
                signerSetVersion,
                deadline
            )
        );
    }

    function _decisionStruct(
        bytes32 action,
        bytes32 genesisHash,
        uint256 expectedAmount,
        uint256 nonce,
        uint256 deadline
    ) internal pure returns (bytes32) {
        return keccak256(
            abi.encode(
                keccak256(
                    "Decision(bytes32 action,bytes32 genesisHash,uint256 expectedAmount,uint256 nonce,uint256 deadline)"
                ),
                action,
                genesisHash,
                expectedAmount,
                nonce,
                deadline
            )
        );
    }

    // ------------------------------------------------------------------
    // Signatures
    // ------------------------------------------------------------------

    function _sign(uint256 key, bytes32 digest) internal returns (bytes memory) {
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(key, digest);
        return abi.encodePacked(r, s, v);
    }

    function _sign2(uint256 keyA, uint256 keyB, bytes32 digest) internal returns (bytes[] memory sigs) {
        sigs = new bytes[](2);
        sigs[0] = _sign(keyA, digest);
        sigs[1] = _sign(keyB, digest);
    }

    function _sign3(uint256 keyA, uint256 keyB, uint256 keyC, bytes32 digest)
        internal
        returns (bytes[] memory sigs)
    {
        sigs = new bytes[](3);
        sigs[0] = _sign(keyA, digest);
        sigs[1] = _sign(keyB, digest);
        sigs[2] = _sign(keyC, digest);
    }

    function _split(bytes memory sig) internal pure returns (bytes32 r, bytes32 s, uint8 v) {
        require(sig.length == 65, "signature length");
        uint256 rWord;
        uint256 sWord;
        for (uint256 i; i < 32; ++i) {
            rWord = (rWord << 8) | uint8(sig[i]);
            sWord = (sWord << 8) | uint8(sig[32 + i]);
        }
        r = bytes32(rWord);
        s = bytes32(sWord);
        v = uint8(sig[64]);
    }

    /// The other valid-looking ECDSA form of the same signature: (r, n - s, v ^ 1).
    /// ecrecover accepts it and returns the same signer; OpenZeppelin rejects s > n / 2.
    function _malleate(bytes memory sig) internal pure returns (bytes memory) {
        (bytes32 r, bytes32 s, uint8 v) = _split(sig);
        return abi.encodePacked(r, bytes32(SECP256K1_N - uint256(s)), v == 27 ? uint8(28) : uint8(27));
    }

    /// EIP-2098 64-byte compact form of the same signature.
    function _compact(bytes memory sig) internal pure returns (bytes memory) {
        (bytes32 r, bytes32 s, uint8 v) = _split(sig);
        return abi.encodePacked(r, bytes32(uint256(s) | (uint256(v - 27) << 255)));
    }

    function _withV(bytes memory sig, uint8 newV) internal pure returns (bytes memory) {
        (bytes32 r, bytes32 s, ) = _split(sig);
        return abi.encodePacked(r, s, newV);
    }

    /// A private key that is a valid secp256k1 scalar and not in 1..99, the
    /// range used for configured or candidate signers in these suites.
    function _outsiderKey(uint256 seed) internal pure returns (uint256) {
        return _bound(seed, 100, SECP256K1_N - 1);
    }

    // ------------------------------------------------------------------
    // Low-level calls that never bubble up a revert
    // ------------------------------------------------------------------

    function _try(address target, bytes memory data) internal returns (bool ok, bytes4 selector) {
        bytes memory reason;
        (ok, reason) = target.call(data);
        if (!ok && reason.length >= 4) selector = bytes4(reason);
    }

    function _tryAs(address sender, address target, bytes memory data)
        internal
        returns (bool ok, bytes4 selector)
    {
        vm.prank(sender);
        return _try(target, data);
    }
}
