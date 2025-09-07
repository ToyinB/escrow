;; Escrow Smart Contract
;; This contract facilitates secure transactions between a buyer and seller with an escrow agent

;; Error codes
(define-constant ERR-NOT-AUTHORIZED (err u100))
(define-constant ERR-ALREADY-INITIALIZED (err u101))
(define-constant ERR-NOT-INITIALIZED (err u102))
(define-constant ERR-INVALID-AMOUNT (err u103))
(define-constant ERR-INSUFFICIENT-FUNDS (err u104))
(define-constant ERR-ALREADY-COMPLETED (err u105))
(define-constant ERR-ALREADY-CANCELED (err u106))
(define-constant ERR-WRONG-STATE (err u107))
(define-constant ERR-INVALID-SELLER (err u108))
(define-constant ERR-INVALID-AGENT (err u109))
(define-constant ERR-SAME-PARTY (err u110))
(define-constant ERR-INVALID-PRINCIPAL (err u111))
(define-constant ERR-INVALID-ADDRESS (err u112))
(define-constant ERR-BLACKLISTED (err u113))
(define-constant ERR-NULL-PRINCIPAL (err u114))

;; Contract variables
(define-data-var contract-owner principal tx-sender)
(define-data-var escrow-fee uint u10) ;; Fee in basis points (0.1%)

;; Transaction status enumeration
(define-constant STATUS-PENDING u0)
(define-constant STATUS-COMPLETED u1)
(define-constant STATUS-CANCELED u2)

;; Maps for access control and security
(define-map approved-agents principal bool)
(define-map blacklisted-addresses principal bool)
(define-map valid-addresses principal bool)

;; Escrow structure
(define-map escrows
    uint
    {
        buyer: principal,
        seller: principal,
        agent: principal,
        amount: uint,
        fee: uint,
        status: uint,
        created-at: uint,
        completed-at: (optional uint),
        canceled-at: (optional uint)
    }
)

;; Counter for escrow IDs
(define-data-var escrow-counter uint u0)

;; Enhanced helper functions for input validation
(define-private (validate-principal (address principal))
    (begin
        (asserts! (not (is-eq address tx-sender)) ERR-INVALID-PRINCIPAL)
        (asserts! (not (is-eq address (var-get contract-owner))) ERR-INVALID-PRINCIPAL)
        (ok true)
    )
)

(define-private (is-contract-address (address principal))
    (begin
        (try! (validate-principal address))
        (ok (is-eq address (as-contract tx-sender)))
    )
)

(define-private (is-reserved-address (address principal))
    (begin
        (try! (validate-principal address))
        (ok (or
            (is-eq address tx-sender)
            (is-eq address (var-get contract-owner))
            (unwrap! (is-contract-address address) ERR-INVALID-ADDRESS)
        ))
    )
)

(define-private (check-blacklist (address principal))
    (begin
        (try! (validate-principal address))
        (asserts! (not (unwrap! (is-reserved-address address) ERR-INVALID-ADDRESS)) ERR-INVALID-ADDRESS)
        (ok (not (default-to false (map-get? blacklisted-addresses address))))
    )
)

(define-private (check-whitelisted (address principal))
    (begin
        (try! (validate-principal address))
        (asserts! (not (unwrap! (is-reserved-address address) ERR-INVALID-ADDRESS)) ERR-INVALID-ADDRESS)
        (ok (default-to false (map-get? valid-addresses address)))
    )
)

(define-private (is-valid-address (address principal))
    (begin
        (try! (validate-principal address))
        (asserts! (not (unwrap! (is-reserved-address address) ERR-INVALID-ADDRESS)) ERR-INVALID-ADDRESS)
        (asserts! (unwrap! (check-blacklist address) ERR-BLACKLISTED) ERR-INVALID-ADDRESS)
        (ok true)
    )
)

(define-private (validate-and-store-address (address principal))
    (begin
        (try! (validate-principal address))
        (asserts! (not (unwrap! (is-reserved-address address) ERR-INVALID-ADDRESS)) ERR-INVALID-ADDRESS)
        (try! (is-valid-address address))
        (ok (map-set valid-addresses address true))
    )
)

(define-private (are-different-principals (p1 principal) (p2 principal) (p3 principal))
    (begin
        (try! (validate-principal p2))
        (try! (validate-principal p3))
        (asserts! (not (unwrap! (is-reserved-address p2) ERR-INVALID-ADDRESS)) ERR-INVALID-ADDRESS)
        (asserts! (not (unwrap! (is-reserved-address p3) ERR-INVALID-ADDRESS)) ERR-INVALID-ADDRESS)
        (ok (and
            (not (is-eq p1 p2))
            (not (is-eq p2 p3))
            (not (is-eq p1 p3))
        ))
    )
)

;; Administrative functions for security management
(define-public (add-approved-agent (address principal))
    (begin
        (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
        (try! (validate-principal address))
        (asserts! (not (unwrap! (is-reserved-address address) ERR-INVALID-ADDRESS)) ERR-INVALID-ADDRESS)
        (try! (is-valid-address address))
        (try! (validate-and-store-address address))
        (ok (map-set approved-agents address true))
    )
)

(define-public (remove-approved-agent (address principal))
    (begin
        (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
        (try! (validate-principal address))
        (asserts! (not (unwrap! (is-reserved-address address) ERR-INVALID-ADDRESS)) ERR-INVALID-ADDRESS)
        (asserts! (unwrap! (check-whitelisted address) ERR-INVALID-ADDRESS) ERR-INVALID-ADDRESS)
        (map-delete valid-addresses address)
        (ok (map-delete approved-agents address))
    )
)

(define-public (blacklist-address (address principal))
    (begin
        (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
        (try! (validate-principal address))
        (asserts! (not (unwrap! (is-reserved-address address) ERR-INVALID-ADDRESS)) ERR-INVALID-ADDRESS)
        (try! (is-valid-address address))
        (map-delete valid-addresses address)
        (map-delete approved-agents address)
        (ok (map-set blacklisted-addresses address true))
    )
)

;; Initialize a new escrow transaction
(define-public (create-escrow (seller-addr principal) (agent-addr principal) (amount uint))
    (let
        (
            (escrow-id (+ (var-get escrow-counter) u1))
            (fee-amount (/ (* amount (var-get escrow-fee)) u10000))
            (total-amount (+ amount fee-amount))
        )
        ;; Enhanced input validation
        (try! (validate-principal seller-addr))
        (try! (validate-principal agent-addr))
        (asserts! (not (unwrap! (is-reserved-address seller-addr) ERR-INVALID-ADDRESS)) ERR-INVALID-ADDRESS)
        (asserts! (not (unwrap! (is-reserved-address agent-addr) ERR-INVALID-ADDRESS)) ERR-INVALID-ADDRESS)
        (try! (is-valid-address seller-addr))
        (try! (is-valid-address agent-addr))
        (try! (validate-and-store-address seller-addr))
        (try! (validate-and-store-address agent-addr))
        (asserts! (default-to false (map-get? approved-agents agent-addr)) ERR-INVALID-AGENT)
        (asserts! (unwrap! (are-different-principals tx-sender seller-addr agent-addr) ERR-SAME-PARTY) ERR-SAME-PARTY)
        (asserts! (> amount u0) ERR-INVALID-AMOUNT)
        
        ;; Transfer STX to contract
        (try! (stx-transfer? total-amount tx-sender (as-contract tx-sender)))
        
        ;; Create escrow record
        (map-set escrows
            escrow-id
            {
                buyer: tx-sender,
                seller: seller-addr,
                agent: agent-addr,
                amount: amount,
                fee: fee-amount,
                status: STATUS-PENDING,
                created-at: block-height,
                completed-at: none,
                canceled-at: none
            }
        )
        
        ;; Increment counter
        (var-set escrow-counter escrow-id)
        (ok escrow-id)
    )
)

;; Update escrow fee (only contract owner)
(define-public (set-escrow-fee (new-fee uint))
    (begin
        (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
        (asserts! (<= new-fee u1000) ERR-INVALID-AMOUNT) ;; Max fee 10%
        (var-set escrow-fee new-fee)
        (ok true)
    )
)

;; Transfer contract ownership
(define-public (transfer-ownership (new-addr principal))
    (begin
        (asserts! (is-eq tx-sender (var-get contract-owner)) ERR-NOT-AUTHORIZED)
        (try! (validate-principal new-addr))
        (asserts! (not (unwrap! (is-reserved-address new-addr) ERR-INVALID-ADDRESS)) ERR-INVALID-ADDRESS)
        (try! (is-valid-address new-addr))
        (try! (validate-and-store-address new-addr))
        (var-set contract-owner new-addr)
        (ok true)
    )
)