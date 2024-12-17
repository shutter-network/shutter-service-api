-- +goose Up
-- +goose StatementBegin
CREATE TABLE decryption_key (
       eon bigint,
       epoch_id bytea,
       decryption_key bytea,
       PRIMARY KEY (eon, epoch_id)
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DROP TABLE decryption_key;
DROP TABLE identity_registered_event;
-- +goose StatementEnd
