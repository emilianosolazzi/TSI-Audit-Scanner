// SPDX-License-Identifier: MIT
pragma solidity 0.8.30;

import "forge-std/Test.sol";
import {TSIBase} from "src/core/TSIBase.sol";
import {Contradiction, TSISeverity} from "src/core/TSITypes.sol";
import {ERC4626DonationPreviewAdapter} from "src/adapters/ERC4626DonationPreviewAdapter.sol";
import {MockERC4626DonationVault} from "test/helpers/TSIMockProtocols.sol";

contract ERC4626DonationPreviewAdapterTest is Test, TSIBase {
    MockERC4626DonationVault internal vault;
    ERC4626DonationPreviewAdapter internal adapter;

    function setUp() public {
        vault = new MockERC4626DonationVault(1_000 ether, 1_000 ether);
        adapter = new ERC4626DonationPreviewAdapter(address(vault));
    }

    function test_detects_preview_invalidation_after_same_block_donation() public {
        bytes memory context = abi.encode(100 ether);
        adapter.executeExploit(abi.encode(100 ether, 400 ether));

        Contradiction memory contradiction = assertContradiction(
            adapter,
            context,
            "expected ERC4626 donation preview contradiction"
        );

        assertGt(uint256(contradiction.tau1.numericValue), uint256(contradiction.tau2.numericValue));
        assertMinimumSeverity(scoreContradiction(adapter, context, 85), TSISeverity.HIGH, "expected HIGH severity");
    }

    function test_no_contradiction_without_donation_shift() public view {
        Contradiction memory contradiction = captureContradiction(adapter, abi.encode(100 ether));
        assertFalse(contradiction.contradiction, "unexpected ERC4626 preview contradiction");
    }
}