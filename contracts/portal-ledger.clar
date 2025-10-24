;; portal-ledger: Cross-Realm NFT Bridge Contract
;; 
;; Core infrastructure for managing cross-realm digital assets and their metadata
;; across distinct virtual environments. Maintains canonical records of asset origins,
;; attributes, capabilities, and transformation rules for multi-environment deployment.

;; ==========================================
;; Error Code Definitions
;; ==========================================

(define-constant error-unauthorized (err u100))
(define-constant fail-realm-duplicate (err u101))
(define-constant fail-realm-missing (err u102))
(define-constant fail-asset-registered (err u103))
(define-constant fail-asset-unknown (err u104))
(define-constant fail-attr-type-missing (err u105))
(define-constant fail-feature-unknown (err u106))
(define-constant fail-bridge-active (err u107))
(define-constant fail-bridge-inactive (err u108))
(define-constant fail-royalty-limit (err u109))
(define-constant fail-invalid-args (err u110))
(define-constant fail-feature-exists (err u111))
(define-constant fail-attr-type-exists (err u112))

;; ==========================================
;; State Variables and Data Maps
;; ==========================================

;; Administrative principal with special privileges
(define-data-var master-principal principal tx-sender)

;; Bridge rule registry (for cross-realm translations)
(define-map portal-registry
  { portal-id: (string-ascii 50) }
  {
    title: (string-ascii 100),
    operator: principal,
    endpoint-url: (optional (string-ascii 255)),
    details: (string-utf8 500),
    setup-block: uint,
    operational: bool
  }
)

;; Reverse index: operator to portal list
(define-map portal-index-by-operator
  { operator: principal }
  { portal-list: (list 20 (string-ascii 50)) }
)

;; Asset ledger (canonical asset definitions)
(define-map asset-ledger
  { asset-id: (string-ascii 50) }
  {
    asset-title: (string-ascii 100),
    originating-portal-id: (string-ascii 50),
    author: principal,
    origin-height: uint,
    info-uri: (string-ascii 255),
    creator-share: uint,
    live: bool
  }
)

;; Characteristic types (attribute schema)
(define-map attribute-schema
  { schema-id: (string-ascii 50) }
  {
    label: (string-ascii 100),
    notes: (string-utf8 500),
    defined-by: principal,
    defined-at-height: uint
  }
)

;; Asset attribute values
(define-map asset-attributes
  { asset-id: (string-ascii 50), schema-id: (string-ascii 50) }
  {
    attr-value: (string-utf8 255)
  }
)

;; Feature set definitions
(define-map feature-set
  { feature-id: (string-ascii 50) }
  {
    feature-name: (string-ascii 100),
    specification: (string-utf8 500),
    defined-by: principal,
    defined-at-height: uint
  }
)

;; Asset feature mapping (what features are enabled on which assets)
(define-map asset-features
  { asset-id: (string-ascii 50), feature-id: (string-ascii 50) }
  {
    is-enabled: bool,
    config: (optional (string-utf8 1000))
  }
)

;; Bridge definitions (cross-portal transformation rules)
(define-map bridge-mapping
  { asset-id: (string-ascii 50), origin-portal-id: (string-ascii 50), dest-portal-id: (string-ascii 50) }
  {
    display-title: (string-ascii 100),
    resource-uri: (string-ascii 255), 
    spec-data: (string-utf8 1000),
    authored-by: principal,
    authored-at-height: uint,
    last-modified-height: uint
  }
)

;; ==========================================
;; Helper Functions (Private)
;; ==========================================

;; Verify if transaction sender holds administrative authority
(define-private (check-master-access)
  (is-eq tx-sender (var-get master-principal))
)

;; Query whether principal operates a specific portal
(define-private (check-portal-operator (portal-id (string-ascii 50)))
  (match (map-get? portal-registry { portal-id: portal-id })
    portal-entry (is-eq tx-sender (get operator portal-entry))
    false
  )
)

;; Composite authorization for portal modification
(define-private (authorized-portal-action (portal-id (string-ascii 50)))
  (or (check-master-access) (check-portal-operator portal-id))
)

;; Check asset authorship
(define-private (check-asset-author (asset-id (string-ascii 50)))
  (match (map-get? asset-ledger { asset-id: asset-id })
    record (is-eq tx-sender (get author record))
    false
  )
)

;; Verify asset modification rights
(define-private (authorized-asset-action (asset-id (string-ascii 50)))
  (or (check-master-access) (check-asset-author asset-id))
)

;; Register or append to portal list for an operator
(define-private (index-portal-for-operator (operator principal) (portal-id (string-ascii 50)))
  (match (map-get? portal-index-by-operator { operator: operator })
    index-record (map-set portal-index-by-operator 
                    { operator: operator }
                    { portal-list: (unwrap-panic (as-max-len? (append (get portal-list index-record) portal-id) u20)) })
    (map-set portal-index-by-operator 
              { operator: operator }
              { portal-list: (list portal-id) })
  )
)

;; ==========================================
;; Read-Only Query Functions
;; ==========================================

;; Fetch portal entry details
(define-read-only (query-portal (portal-id (string-ascii 50)))
  (map-get? portal-registry { portal-id: portal-id })
)

;; List all portals managed by a given operator
(define-read-only (fetch-operator-portals (operator principal))
  (match (map-get? portal-index-by-operator { operator: operator })
    record (get portal-list record)
    (list)
  )
)

;; Retrieve asset metadata
(define-read-only (retrieve-asset (asset-id (string-ascii 50)))
  (map-get? asset-ledger { asset-id: asset-id })
)

;; Look up attribute type definition
(define-read-only (read-schema (schema-id (string-ascii 50)))
  (map-get? attribute-schema { schema-id: schema-id })
)

;; Retrieve attribute value for an asset
(define-read-only (read-asset-attribute (asset-id (string-ascii 50)) (schema-id (string-ascii 50)))
  (map-get? asset-attributes { asset-id: asset-id, schema-id: schema-id })
)

;; Get feature definition
(define-read-only (query-feature (feature-id (string-ascii 50)))
  (map-get? feature-set { feature-id: feature-id })
)

;; Retrieve feature enablement status for an asset
(define-read-only (read-asset-feature (asset-id (string-ascii 50)) (feature-id (string-ascii 50)))
  (map-get? asset-features { asset-id: asset-id, feature-id: feature-id })
)

;; Get bridge configuration
(define-read-only (retrieve-bridge-rule (asset-id (string-ascii 50)) (origin-portal-id (string-ascii 50)) (dest-portal-id (string-ascii 50)))
  (map-get? bridge-mapping { asset-id: asset-id, origin-portal-id: origin-portal-id, dest-portal-id: dest-portal-id })
)

;; Check if asset can operate within a portal (direct or via bridge)
(define-read-only (test-asset-portal-compatibility (asset-id (string-ascii 50)) (portal-id (string-ascii 50)))
  (match (map-get? asset-ledger { asset-id: asset-id })
    asset-record (if (is-eq (get originating-portal-id asset-record) portal-id)
              true
              (is-some (map-get? bridge-mapping { 
                asset-id: asset-id, 
                origin-portal-id: (get originating-portal-id asset-record), 
                dest-portal-id: portal-id 
              })))
    false
  )
)

;; ==========================================
;; Public State-Modifying Functions
;; ==========================================

;; Transfer administrative authority to new principal
(define-public (transfer-master-authority (recipient principal))
  (begin
    (asserts! (check-master-access) error-unauthorized)
    (ok (var-set master-principal recipient))
  )
)

;; Establish a new realm portal
(define-public (establish-portal 
  (portal-id (string-ascii 50)) 
  (title (string-ascii 100)) 
  (endpoint-url (optional (string-ascii 255))) 
  (details (string-utf8 500)))
  (begin
    (asserts! (is-none (map-get? portal-registry { portal-id: portal-id })) fail-realm-duplicate)
    
    (map-set portal-registry 
      { portal-id: portal-id }
      {
        title: title,
        operator: tx-sender,
        endpoint-url: endpoint-url,
        details: details,
        setup-block: block-height,
        operational: true
      }
    )
    
    (index-portal-for-operator tx-sender portal-id)
    
    (ok true)
  )
)


;; Register a canonical asset within the ledger
(define-public (register-cross-realm-asset 
  (asset-id (string-ascii 50))
  (asset-title (string-ascii 100))
  (originating-portal-id (string-ascii 50))
  (info-uri (string-ascii 255))
  (creator-share uint))
  (begin
    (asserts! (is-some (map-get? portal-registry { portal-id: originating-portal-id })) fail-realm-missing)
    
    (asserts! (authorized-portal-action originating-portal-id) error-unauthorized)
    
    (asserts! (is-none (map-get? asset-ledger { asset-id: asset-id })) fail-asset-registered)
    
    (asserts! (<= creator-share u3000) fail-royalty-limit)
    
    (map-set asset-ledger
      { asset-id: asset-id }
      {
        asset-title: asset-title,
        originating-portal-id: originating-portal-id,
        author: tx-sender,
        origin-height: block-height,
        info-uri: info-uri,
        creator-share: creator-share,
        live: true
      }
    )
    
    (ok true)
  )
)


;; Define a new asset attribute type
(define-public (define-attribute-type
  (schema-id (string-ascii 50))
  (label (string-ascii 100))
  (notes (string-utf8 500)))
  (begin
    (asserts! (check-master-access) error-unauthorized)
    
    (asserts! (is-none (map-get? attribute-schema { schema-id: schema-id })) fail-attr-type-exists)
    
    (map-set attribute-schema
      { schema-id: schema-id }
      {
        label: label,
        notes: notes,
        defined-by: tx-sender,
        defined-at-height: block-height
      }
    )
    
    (ok true)
  )
)


;; Assign attribute value to an asset
(define-public (assign-asset-attribute
  (asset-id (string-ascii 50))
  (schema-id (string-ascii 50))
  (attr-value (string-utf8 255)))
  (begin
    (asserts! (is-some (map-get? asset-ledger { asset-id: asset-id })) fail-asset-unknown)
    
    (asserts! (is-some (map-get? attribute-schema { schema-id: schema-id })) fail-attr-type-missing)
    
    (asserts! (authorized-asset-action asset-id) error-unauthorized)
    
    (map-set asset-attributes
      { asset-id: asset-id, schema-id: schema-id }
      { attr-value: attr-value }
    )
    
    (ok true)
  )
)


;; Introduce a new cross-realm feature
(define-public (introduce-feature
  (feature-id (string-ascii 50))
  (feature-name (string-ascii 100))
  (specification (string-utf8 500)))
  (begin
    (asserts! (check-master-access) error-unauthorized)
    
    (asserts! (is-none (map-get? feature-set { feature-id: feature-id })) fail-feature-exists)
    
    (map-set feature-set
      { feature-id: feature-id }
      {
        feature-name: feature-name,
        specification: specification,
        defined-by: tx-sender,
        defined-at-height: block-height
      }
    )
    
    (ok true)
  )
)


;; Configure asset feature activation
(define-public (configure-asset-feature
  (asset-id (string-ascii 50))
  (feature-id (string-ascii 50))
  (is-enabled bool)
  (config (optional (string-utf8 1000))))
  (begin
    (asserts! (is-some (map-get? asset-ledger { asset-id: asset-id })) fail-asset-unknown)
    
    (asserts! (is-some (map-get? feature-set { feature-id: feature-id })) fail-feature-unknown)
    
    (asserts! (authorized-asset-action asset-id) error-unauthorized)
    
    (map-set asset-features
      { asset-id: asset-id, feature-id: feature-id }
      { 
        is-enabled: is-enabled,
        config: config
      }
    )
    
    (ok true)
  )
)


;; Establish a cross-realm asset bridge
(define-public (establish-bridge
  (asset-id (string-ascii 50))
  (dest-portal-id (string-ascii 50))
  (display-title (string-ascii 100))
  (resource-uri (string-ascii 255))
  (spec-data (string-utf8 1000)))
  (begin
    (asserts! (is-some (map-get? asset-ledger { asset-id: asset-id })) fail-asset-unknown)
    
    (asserts! (is-some (map-get? portal-registry { portal-id: dest-portal-id })) fail-realm-missing)
    
    (match (map-get? asset-ledger { asset-id: asset-id })
      asset-record
        (let ((origin-portal-id (get originating-portal-id asset-record)))
          (asserts! (or 
            (check-asset-author asset-id) 
            (check-portal-operator dest-portal-id)
            (check-master-access)
          ) error-unauthorized)
          
          (asserts! (is-none (map-get? bridge-mapping { 
            asset-id: asset-id, 
            origin-portal-id: origin-portal-id, 
            dest-portal-id: dest-portal-id 
          })) fail-bridge-active)
          
          (map-set bridge-mapping
            { asset-id: asset-id, origin-portal-id: origin-portal-id, dest-portal-id: dest-portal-id }
            {
              display-title: display-title,
              resource-uri: resource-uri,
              spec-data: spec-data,
              authored-by: tx-sender,
              authored-at-height: block-height,
              last-modified-height: block-height
            }
          )
          
          (ok true)
        )
      error-unauthorized
    )
  )
)


;; Revoke an active cross-realm bridge
(define-public (revoke-bridge
  (asset-id (string-ascii 50))
  (origin-portal-id (string-ascii 50))
  (dest-portal-id (string-ascii 50)))
  (begin
    (asserts! (is-some (map-get? bridge-mapping { 
      asset-id: asset-id, 
      origin-portal-id: origin-portal-id, 
      dest-portal-id: dest-portal-id 
    })) fail-bridge-inactive)
    
    (asserts! (or 
      (check-asset-author asset-id) 
      (check-portal-operator dest-portal-id)
      (check-master-access)
    ) error-unauthorized)
    
    (map-delete bridge-mapping { 
      asset-id: asset-id, 
      origin-portal-id: origin-portal-id, 
      dest-portal-id: dest-portal-id 
    })
    
    (ok true)
  )
)