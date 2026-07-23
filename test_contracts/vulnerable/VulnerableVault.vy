# @version 0.3.10
# Vyper test contract — INTENTIONAL VULNERABILITIES for scanner testing.
# Reentrancy via raw_call, missing access control on fee setting,
# unchecked external call return values.

interface ERC20:
    def transfer(_to: address, _value: uint256) -> bool: nonpayable
    def balanceOf(_owner: address) -> uint256: view


balances: public(HashMap[address], uint256])
owner: public(address)
fee_bps: public(uint256)


@external
def __init__():
    self.owner = msg.sender


@external
@payable
def deposit():
    self.balances[msg.sender] += msg.value


# VULN: reentrancy — uses raw_call before state update
@external
def withdraw(_amount: uint256):
    assert self.balances[msg.sender] >= _amount
    # raw_call BEFORE state update -> classic reentrancy
    success: bool = raw_call(
        msg.sender,
        convert(_amount, uint256),
        value=convert(_amount, uint256),
        gas=200000,
    )
    assert success
    self.balances[msg.sender] -= _amount  # state update AFTER external call


# VULN: missing access control — anyone can become owner
@external
def set_owner(_new_owner: address):
    self.owner = _new_owner


# VULN: missing access control — anyone can set fee to 100%
@external
def set_fee(_fee_bps: uint256):
    self.fee_bps = _fee_bps


# VULN: unchecked return value on token transfer
@external
def rescue_token(_token: address, _to: address, _amount: uint256):
    ERC20(_token).transfer(_to, _amount)  # return value ignored
