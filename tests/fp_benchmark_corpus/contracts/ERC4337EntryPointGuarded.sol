pragma solidity 0.8.20;

contract ERC4337EntryPointGuarded {
    mapping(address => uint256) public nonceSequence;
    mapping(address => uint256) public deposits;

    function depositTo(address account) external payable {
        require(account != address(0), "zero account");
        deposits[account] += msg.value;
    }

    function handleOp(address sender, uint256 nonce, uint256 requiredPrefund) external returns (bool) {
        require(nonce == nonceSequence[sender], "bad nonce");
        require(deposits[sender] >= requiredPrefund, "missing prefund");
        nonceSequence[sender] += 1;
        deposits[sender] -= requiredPrefund;
        return true;
    }
}