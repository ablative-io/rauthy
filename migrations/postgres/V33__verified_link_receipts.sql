-- Earlier text acknowledgements are retained, but do not claim cryptographic verification.
ALTER TABLE identity_link_audit ADD COLUMN receipt_verified BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE identity_link_audit ADD CONSTRAINT identity_link_receipt_verified_evidence
    CHECK (NOT receipt_verified OR (receipt IS NOT NULL AND acknowledged_at IS NOT NULL AND lys_person IS NOT NULL));
UPDATE identity_link_format SET version=2 WHERE id=1;
