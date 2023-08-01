---
title: "0day: Vyper nonreentrant lock bypass, enabling cross function reentrancy"
date: 2023-08-02T01:31:00+03:00
draft: true
---

On Sunday, 30th July, tragedy struck as a vyper compiler bug was dug up from the past. This document is intended as a technical educational resource to demystify exactly what happened on the compiler side only ahead of the Vyper team's official post mortem for impatient individuals such as myself.

If you're looking for post mortems of protocols exploited with this vulnerability, Curve released one under [Llama Risk](https://hackmd.io/@LlamaRisk/BJzSKHNjn). Other affected protocols have yet to release theirs. If you'd like to know where the exploited funds ended up, Taylor Monahan(tayvano) released [data](https://twitter.com/tayvano_/status/1685789453556846592) on this topic.

With that out of the way, let's dive into the bug.

Vyper contracts compiled with versions 0.2.15 - 0.3.0 are all affected by this vulnerability.

This vulnerability was introduced in this [pull request](https://github.com/vyperlang/vyper/pull/2391/files) in the file `data_positions.py`, lines 28 to 35 as a fix to a previous issue. 

Note: The code snippets below are from the relevant functions in the PRs linked. I include the full function definition but only explain what is relevant to the bug.

```python
def set_storage_slots(vyper_module: vy_ast.Module) -> None:
    """
    Parse module-level Vyper AST to calculate the layout of storage variables.
    """
    # Allocate storage slots from 0
    # note storage is word-addressable, not byte-addressable
    storage_slot = 0

    for node in vyper_module.get_children(vy_ast.FunctionDef):
        type_ = node._metadata["type"]
        if type_.nonreentrant is not None:
            type_.set_reentrancy_key_position(StorageSlot(storage_slot))
            # TODO use one byte - or bit - per reentrancy key
            # requires either an extra SLOAD or caching the value of the
            # location in memory at entrance
            storage_slot += 1

    for node in vyper_module.get_children(vy_ast.AnnAssign):
        type_ = node.target._metadata["type"]
        type_.set_position(StorageSlot(storage_slot))
        # CMC 2021-07-23 note that HashMaps get assigned a slot here.
        # I'm not sure if it's safe to avoid allocating that slot
        # for HashMaps because downstream code might use the slot
        # ID as a salt.
        storage_slot += math.ceil(type_.size_in_bytes / 32)
```

The function above receives an Abstract Syntax Tree(AST) of a vyper module as an argument An AST is a tree-like representation of the source code that respects the rules of the language allowing for easier manipulation and analysis. They help the computer understand the order of operations, variable assignments, function calls, loops, conditionals, and much more.

It then iterates over the function definitions present in a given vyper module and checks if they have the nonreentrant decorator. If they do, it then assigns a storage slot to the decorator.

As observed in the code, the storage slot position increments with each iteration. There's no logic to check whether a nonreentrant decorator has already been assigned to a storage slot so each additional nonreentrant decorator is assigned to a new slot instead of sharing one. You can think of it like storing the mutex for each individual function's lock in different variables.

In practice, this means vyper contract functions are protected from single function reentrancy but vulnerable to cross-function reentrancy. To better illustrate this, I will write a simple vyper code example to show what's happening under the hood.

```vyper
userBalances: HashMap[address, uint256]
lock_key_1: bool
lock_key_2: bool

@external
@payable
def deposit():
    self.userBalances[msg.sender] += msg.value

@external
def withdraw(_amount: uint256):
	assert not self.lock_key_1, "No re-entrancy"
	self.lock_key_1 = True
    assert self.userBalances[msg.sender] >= _amount
    send(msg.sender, _amount)
    self.userBalances[msg.sender] -= _amount
    self.lock_key_1 = False

@external
def withdrawAll():
	assert not self.lock_key_2, "No re-entrancy"
	self.lock_key_2 = True
    balance: uint256 = self.getUserBalance(msg.sender)
    assert balance > 0
    send(msg.sender, balance)
    self.userBalances[msg.sender] = 0
    self.lock_key_2 = False

@view
@external
def getBalance() -> uint256:
    return self.balance

@view
@external
def getUserBalance(_user: address) -> uint256:
    return self.userBalances[_user]
```

Assuming you're familiar with reentrancy at a base level, you know the exploit would fail when trying to initiate reentrancy on `withdrawAll();` alone since the contract call is still ongoing and `lock_key_2` is true.

However if we called `withdraw()` within our `receive()` function with the value of our balance and our wallet address, we'd essentially get double what we put in. The function call would not fail since `lock_key_1` isn't set to true just yet. Once the call is done, we can just repeat the same sequence until the pool is empty.

The ethereum ecosystem today has a plethora of tools for detecting and monitoring suspicious activity on specific contracts so the above approach would mean an exploiter would likely be detected by the deployers(if they know what they're doing), thus reducing the potential impact of their attack, assuming the deployers paused the contracts in time.

However, since the advent of flashloans, black hats can take out a loan of large enough size to drain a contract and repay it in one transaction while retaining the profit over executing the same exploit with their own likely miniscule funds i.e 1 or 2 ETH to counter that.

## Fix

The vulnerability was patched uintentionally with this [PR](https://github.com/vyperlang/vyper/pull/2439) and this [PR](https://github.com/vyperlang/vyper/pull/2514) in the 0.3.1 release. The term "unintentionally" is used here because the rationale behind these changes was rooted in optimization, not specifically vulnerability mitigation as the contributors were not aware of the bug at the time.

The below code snippet was extracted from the latter PR.

```python
def set_storage_slots(vyper_module: vy_ast.Module) -> StorageLayout:
    """
    Parse module-level Vyper AST to calculate the layout of storage variables.
    Returns the layout as a dict of variable name -> variable info
    """
    # Allocate storage slots from 0
    # note storage is word-addressable, not byte-addressable
    storage_slot = 0

    ret: Dict[str, Dict] = {}

    for node in vyper_module.get_children(vy_ast.FunctionDef):
        type_ = node._metadata["type"]
        if type_.nonreentrant is None:
            continue

        variable_name = f"nonreentrant.{type_.nonreentrant}"

        # a nonreentrant key can appear many times in a module but it
        # only takes one slot. after the first time we see it, do not
        # increment the storage slot.
        if variable_name in ret:
            _slot = ret[variable_name]["slot"]
            type_.set_reentrancy_key_position(StorageSlot(_slot))
            continue

        type_.set_reentrancy_key_position(StorageSlot(storage_slot))

        # TODO this could have better typing but leave it untyped until
        # we nail down the format better
        ret[variable_name] = {
            "type": "nonreentrant lock",
            "location": "storage",
            "slot": storage_slot,
        }

        # TODO use one byte - or bit - per reentrancy key
        # requires either an extra SLOAD or caching the value of the
        # location in memory at entrance
        storage_slot += 1
```

The updated code declares a new dictionary, `ret`, with strings as keys and dictionaries as their corresponding values. It is then returned at the end of the execution. `ret` stores information (type, location, and slot) for each variable. This proves crucial as it allows the code to check if a nonreentrant decorator has been recorded previously. If not, the code will set the key position with `storage_slot`, increment it and record the information in `ret`. If so, the code now fetches its storage slot from `ret`, and assigns other nonreentrant decorators to the same slot. As a result, all mutexes share the same state.

Again, I'll refactor the above vyper code to help you visualise this.

```Vyper
userBalances: HashMap[address, uint256]
lock_key: bool

@external
@payable
def deposit():
    self.userBalances[msg.sender] += msg.value

@external
def withdraw(_amount: uint256):
	assert not self.lock_key, "No re-entrancy"
	self.lock_key_1 = True
    assert self.userBalances[msg.sender] >= _amount
    send(msg.sender, _amount)
    self.userBalances[msg.sender] -= _amount
    self.lock_key_1 = False

@external
def withdrawAll():
	assert not self.lock_key, "No re-entrancy"
	self.lock_key = True
    balance: uint256 = self.getUserBalance(msg.sender)
    assert balance > 0
    send(msg.sender, balance)
    self.userBalances[msg.sender] = 0
    self.lock_key = False

@view
@external
def getBalance() -> uint256:
    return self.balance

@view
@external
def getUserBalance(_user: address) -> uint256:
    return self.userBalances[_user]
```

The resulting Vyper code, post patch, would look something like this. Since only one storage location is used for all the locks, cross-function reentrancy becomes an impossibility.

Note: This is written by an outside observer with limited understanding of the compiler code using clues left behind by various community efforts aggregated into an understandable piece of media. As a result, I cannot guarantee that all the content in here regarding the compiler is correct.

I would like to note that this bug was introduced back when the vyper team was just one active developer and they have evolved since then with a much more robust security process and more contributors. However, we can always improve on that and I invite you to join the effort.

- [GitHub](https://github.com/vyperlang/vyper) - obvious what this is for
- [Discord](https://discord.gg/929gyFWdad) - for comms, support, contribution discussion etc
- [Twitter/X](https://twitter.com/vyperlang)
- [Docs](https://docs.vyperlang.org/en/stable/)

Special shout out to the vyper team(particularly [Charles Cooper](https://twitter.com/big_tech_sux)) for maintaining a beautiful smart contract language that I'd love to see more of in protocol code. It would save me a lot of neurons and energy to review over "optimised" alternatives. Thanks to all the white hats that worked together with them to white hack funds in affected protocols including [pcaversaccio](https://twitter.com/pcaversaccio), [0xaddi](https://twitter.com/0xaddi), coffeebabe and many more. I wasn't privvy to this information so I apologise if you were left out. <3

If you'd like to hear a short update on future actions following this event. Charles released a small update over on [twitter](https://twitter.com/big_tech_sux/status/1686417276680192001) as I wrote this out.

Credits and references:

- [Chaofan Shou](https://twitter.com/shoucccc/status/1685688647637725184) whose twitter post pointed me in the right direction to look into the vyper compiler codebase.
- [ConsenSys Diligence]()'s best practice section on cross-function reentrancy whose code I used as the inspiration for the Vyper code example.
- [Joshua T. Riley](https://twitter.com/jtriley_eth)(jtriley) for proof reading this. <3