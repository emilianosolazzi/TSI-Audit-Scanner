pragma solidity 0.8.20;

library SafeERC20Wrapper {
    function safeTransfer(address token, address to, uint256 value) internal {
        (bool success, bytes memory data) = token.call(abi.encodeWithSignature("transfer(address,uint256)", to, value));
        require(success, "SafeERC20: low-level call failed");
        require(data.length == 0 || abi.decode(data, (bool)), "SafeERC20: operation failed");
    }
}

contract SafeERC20WrapperUser {
    using SafeERC20Wrapper for address;

    function sweep(address token, address recipient, uint256 amount) external {
        token.safeTransfer(recipient, amount);
    }
}