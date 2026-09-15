// Plain Cairo module with an INTENTIONAL accounting bug for scanner testing.
// A refund is credited twice, letting a caller inflate their balance.

pub fn credit_refund(balance: u64, refund: u64) -> u64 {
    // VULN: the refund is applied twice.
    balance + refund + refund
}
