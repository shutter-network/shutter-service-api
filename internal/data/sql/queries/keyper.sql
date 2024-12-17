-- write sql queries here

-- name: GetDecryptionKey :one
SELECT * FROM decryption_key
WHERE eon = $1 AND epoch_id = $2;