// SPDX-License-Identifier: MIT
pragma solidity 0.8.26;

interface Vm {
    function deal(address account, uint256 balance) external;
    function etch(address account, bytes calldata code) external;
    function store(address account, bytes32 key, bytes32 value) external;
    function load(address account, bytes32 key) external view returns (bytes32);
    function prank(address sender) external;
    function readFile(string calldata path) external view returns (string memory);
    function parseBytes(string calldata value) external pure returns (bytes memory);
}

interface Vault {
    function deposit() external payable;
    function withdraw(uint256 amount) external;
    function credit(address account) external view returns (uint256);
}

contract RejectingDepositor {
    function deposit(Vault vault) external payable { vault.deposit{value: msg.value}(); }
    function withdraw(Vault vault, uint256 amount) external { vault.withdraw(amount); }
    receive() external payable { revert("reject transfer"); }
}

contract VaultTest {
    Vm private constant vm = Vm(address(uint160(uint256(keccak256("hevm cheat code")))));
    Vault private constant vault = Vault(address(0x1001));
    address private constant victim = address(0x2001);
    address private constant attacker = address(0x3001);
    bytes32 private constant victimSlot = keccak256(abi.encode(victim, uint256(0)));

    function install(string memory name) private {
        bytes memory text = bytes(vm.readFile(string.concat("../fixtures/compiler/", name, ".runtime.hex")));
        // Compiler tooling emits one newline after the runtime hex.
        bytes memory hexText = new bytes(text.length - 1);
        for (uint256 i; i < hexText.length; ++i) hexText[i] = text[i];
        vm.etch(address(vault), vm.parseBytes(string.concat("0x", string(hexText))));
        vm.deal(address(vault), 10 ether);
        vm.store(address(vault), victimSlot, bytes32(uint256(10 ether)));
        vm.deal(victim, 0);
        vm.deal(attacker, 0);
    }

    function callAs(address sender, bytes memory data, uint256 gasLimit) private returns (bool ok) {
        vm.prank(sender);
        (ok,) = address(vault).call{gas: gasLimit}(data);
    }

    function testVulnerableUnauthorizedWithdrawal() external {
        install("DemoVault");
        bytes32 codeHash = address(vault).codehash;
        require(callAs(attacker, abi.encodeCall(vault.withdraw, (1 ether)), 500_000));
        require(attacker.balance == 1 ether && address(vault).balance == 9 ether);
        require(vault.credit(attacker) == 0 && vault.credit(victim) == 10 ether);
        require(victim.balance == 0 && address(vault).codehash == codeHash);
    }

    function testPatchedRejectsSameUnauthorizedWithdrawal() external {
        install("PatchedVault");
        require(!callAs(attacker, abi.encodeCall(vault.withdraw, (1 ether)), 500_000));
        require(attacker.balance == 0 && address(vault).balance == 10 ether);
        require(vault.credit(victim) == 10 ether && vault.credit(attacker) == 0);
    }

    function testPatchedLegitimateWithdrawalAndRepeatedLimit() external {
        install("PatchedVault");
        require(callAs(victim, abi.encodeCall(vault.withdraw, (4 ether)), 500_000));
        require(victim.balance == 4 ether && vault.credit(victim) == 6 ether);
        require(!callAs(victim, abi.encodeCall(vault.withdraw, (7 ether)), 500_000));
        require(victim.balance == 4 ether && vault.credit(victim) == 6 ether);
        require(callAs(victim, abi.encodeCall(vault.withdraw, (6 ether)), 500_000));
        require(victim.balance == 10 ether && vault.credit(victim) == 0 && address(vault).balance == 0);
    }

    function testPatchedTransferRevertRestoresDebit() external {
        install("PatchedVault");
        RejectingDepositor depositor = new RejectingDepositor();
        vm.deal(address(this), 1 ether);
        depositor.deposit{value: 1 ether}(vault);
        (bool ok,) = address(depositor).call(abi.encodeCall(depositor.withdraw, (vault, 1 ether)));
        require(!ok && vault.credit(address(depositor)) == 1 ether);
        require(address(vault).balance == 11 ether && address(depositor).balance == 0);
    }

    function testVulnerableAmountBoundaries() external {
        uint256[5] memory amounts = [uint256(0), 1, 1 ether, 10 ether, 10 ether + 1];
        for (uint256 i; i < amounts.length; ++i) {
            install("DemoVault");
            bool ok = callAs(attacker, abi.encodeCall(vault.withdraw, (amounts[i])), 500_000);
            bool expected = amounts[i] > 0 && amounts[i] <= 10 ether;
            require(ok == expected);
            require(attacker.balance == (expected ? amounts[i] : 0));
            require(address(vault).balance + attacker.balance == 10 ether);
            require(vault.credit(victim) == 10 ether);
        }
    }

    function testMalformedZeroDepositAndGasExhaustion() external {
        install("DemoVault");
        require(!callAs(attacker, hex"010203", 500_000));
        require(!callAs(attacker, abi.encodeCall(vault.deposit, ()), 500_000));
        require(!callAs(attacker, abi.encodeCall(vault.withdraw, (1 ether)), 100));
        require(address(vault).balance == 10 ether && attacker.balance == 0);
        require(uint256(vm.load(address(vault), victimSlot)) == 10 ether);
    }
}
