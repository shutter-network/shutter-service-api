-- write sql queries here

-- name: GetDecryptionKey :one
SELECT dk.decryption_key
FROM decryption_key dk
INNER JOIN identity_registered_event ire
ON ire.eon = dk.eon AND ire.identity = dk.epoch_id
WHERE ire.identity = $1 AND ire.decrypted = TRUE;