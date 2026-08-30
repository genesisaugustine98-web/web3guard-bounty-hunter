# @version 0.3.10
# INTENTIONAL VULNERABILITIES: reentrancy + missing access control.
balances: public(HashMap[address], uint256])
owner: public(address)
fee_bps: public(uint256)


@external
def __init__():
    self.owner = msg.sender


@external
@payable
def pay():
    self.balances[msg.sender] += msg.value


@external
def claim(_amount: uint256):
    assert self.balances[msg.sender] >= _amount
    success: bool = raw_call(
        msg.sender,
        convert(_amount, uint256),
        value=convert(_amount, uint256),
        gas=200000,
    )
    assert success
    self.balances[msg.sender] -= _amount


@external
def set_fee(_fee_bps: uint256):
    self.fee_bps = _fee_bps
