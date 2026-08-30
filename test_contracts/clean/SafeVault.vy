# @version 0.3.10
# Clean Vyper vault - no reentrancy, no access-control gaps,
# no unchecked external calls. Checks-effects-interactions.
balances: public(HashMap[address], uint256])
owner: public(address)


@external
def __init__():
    self.owner = msg.sender


@external
@payable
def deposit():
    self.balances[msg.sender] += msg.value


@external
def withdraw(_amount: uint256):
    assert self.balances[msg.sender] >= _amount
    self.balances[msg.sender] -= _amount
    send(msg.sender, _amount)
