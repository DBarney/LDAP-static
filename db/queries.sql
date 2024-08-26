-- name: Search :many
SELECT domain, organization, name, attributes FROM entries where domain like ? AND organization like ? AND name like ?;

-- name: FindOne :one
SELECT domain, organization, name, attributes FROM entries where domain = ? AND organization = ? AND name = ? limit 1;

-- name: Insert :exec
INSERT INTO entries (domain, organization, name, attributes) VALUES (?, ?, ?, ?);

-- name: Delete :exec
DELETE FROM entries WHERE domain = ? AND organization = ? AND name = ?;

-- name: Update :exec
UPDATE entries SET attributes = ? WHERE domain = ? AND organization = ? AND name = ?;
