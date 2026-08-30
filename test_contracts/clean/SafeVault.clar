;; Clarity test contract - CLEAN: uses contract-caller for auth,
;; no as-contract? misuse, and documents post-conditions.
;; Post-conditions are defined in the transaction envelope.

(define-data-var owner principal 'ST1PQHQKV0RJXZFY1DGX8MNSNYVE3VGZJSRCPGGD)
(define-data-var post-conditions-enforced bool true)

(define-public (set-owner (new-owner principal))
  (begin
    (asserts! (is-eq contract-caller (var-get owner)) (err u100))
    (var-set owner new-owner)
    (ok true)))
