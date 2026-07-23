;; Clarity test contract — INTENTIONAL VULNERABILITIES for scanner testing.
;; Post-conditions not used, tx-sender vs contract-caller confusion,
;; as-contract? misuse.

(define-data-var owner principal 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRCPGGD)
(define-data-var fee-bps uint u0)

(define-map balances principal uint)

;; VULN: no post-condition — caller can transfer more than the
;; declared amount if the post-condition is missing from the
;; transaction envelope.
(define-public (withdraw (amount uint))
  (begin
    (try! (stx-transfer? amount tx-sender (as-contract tx-sender)))
    (map-set balances tx-sender (- (default-to u0 (map-get? balances tx-sender)) amount))
    (ok true)))

;; VULN: tx-sender vs contract-caller confusion.
;; tx-sender is the original transaction signer, contract-caller is
;; the immediate caller. If this function is invoked from another
;; contract, tx-sender is the *user* but contract-caller is the
;; *contract*. Here the auth check uses tx-sender, so a malicious
;; contract can call this on behalf of a user.
(define-public (set-owner (new-owner principal))
  (begin
    (asserts! (is-eq tx-sender (var-get owner)) (err u100))
    (var-set owner new-owner)
    (ok true)))

;; VULN: as-contract? misuse — changes tx-sender to the contract,
;; bypassing the access check on set-owner above.
(define-public (steal (new-owner principal))
  (begin
    (try! (set-owner new-owner))
    (ok true)))
