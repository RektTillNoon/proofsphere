// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

/// @notice Shared fixture with authorization and debit before interaction.
contract PatchedVault {
    mapping(address => uint256) public credit;

    function deposit() external payable {
        require(msg.value > 0, "zero deposit");
        credit[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(amount > 0, "zero withdrawal");
        require(address(this).balance >= amount, "insufficient balance");
        require(credit[msg.sender] >= amount, "insufficient credit");
        credit[msg.sender] -= amount;
        (bool ok,) = payable(msg.sender).call{value: amount}("");
        require(ok, "transfer failed");
    }
}
