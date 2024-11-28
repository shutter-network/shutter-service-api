-- write schema definitions here

CREATE TABLE decryption_key (
       eon bigint,
       epoch_id bytea,
       decryption_key bytea,
       PRIMARY KEY (eon, epoch_id)
);
