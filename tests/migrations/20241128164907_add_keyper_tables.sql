-- +goose Up
-- +goose StatementBegin
CREATE TABLE decryption_key (
       eon bigint,
       epoch_id bytea,
       decryption_key bytea,
       PRIMARY KEY (eon, epoch_id)
);

CREATE TABLE identity_registered_event (
    block_number bigint NOT NULL CHECK (block_number >= 0),
    block_hash bytea NOT NULL,
    tx_index bigint NOT NULL CHECK (tx_index >= 0),
    log_index bigint NOT NULL CHECK (log_index >= 0),
    eon bigint NOT NULL CHECK (eon >= 0),
    identity_prefix bytea NOT NULL,
    sender text NOT NULL,
    timestamp bigint NOT NULL,
    decrypted boolean NOT NULL DEFAULT false,
    identity bytea NOT NULL,
    PRIMARY KEY (identity_prefix, sender)
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE decryption_key;
DROP TABLE identity_registered_event;
-- +goose StatementEnd
