pragma solidity 0.8.20;

contract ERC4626PreviewSafe {
    uint256 public totalAssetsStored = 1_000 ether;
    uint256 public totalSupplyStored = 1_000 ether;
    uint256 private constant INITIAL_SHARES = 1_000;

    function previewDeposit(uint256 assets) public view returns (uint256) {
        return _convertToShares(assets);
    }

    function deposit(uint256 assets) external returns (uint256 shares) {
        require(assets > 0, "zero assets");
        shares = _convertToShares(assets);
        totalAssetsStored += assets;
        totalSupplyStored += shares;
    }

    function _convertToShares(uint256 assets) internal view returns (uint256) {
        return assets * (totalSupplyStored + INITIAL_SHARES) / (totalAssetsStored + 1);
    }

    function _decimalsOffset() internal pure returns (uint8) {
        return 3;
    }
}