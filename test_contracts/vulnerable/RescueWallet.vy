# @version 0.3.10
# INTENTIONAL VULNERABILITIES: unchecked token transfer + no auth.
owner: public(address)

interface ERC20:
    def transfer(_to: address, _value: uint256) -> bool: nonpayable


@external
def __init__():
    self.owner = msg.sender


@external
def rescue_token(_token: address, _to: address, _amount: uint256):
    ERC20(_token).transfer(_to, _amount)
