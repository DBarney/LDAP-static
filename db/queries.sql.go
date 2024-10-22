// Code generated by sqlc. DO NOT EDIT.
// versions:
//   sqlc v1.15.0
// source: queries.sql

package db

import (
	"context"
)

const delete = `-- name: Delete :exec
DELETE FROM entries WHERE domain = ? AND organization = ? AND name = ?
`

type DeleteParams struct {
	Domain       string
	Organization string
	Name         string
}

func (q *Queries) Delete(ctx context.Context, arg DeleteParams) error {
	_, err := q.db.ExecContext(ctx, delete, arg.Domain, arg.Organization, arg.Name)
	return err
}

const findOne = `-- name: FindOne :one
SELECT domain, organization, name, attributes FROM entries where domain = ? AND organization = ? AND name = ? limit 1
`

type FindOneParams struct {
	Domain       string
	Organization string
	Name         string
}

func (q *Queries) FindOne(ctx context.Context, arg FindOneParams) (Entry, error) {
	row := q.db.QueryRowContext(ctx, findOne, arg.Domain, arg.Organization, arg.Name)
	var i Entry
	err := row.Scan(
		&i.Domain,
		&i.Organization,
		&i.Name,
		&i.Attributes,
	)
	return i, err
}

const insert = `-- name: Insert :exec
INSERT INTO entries (domain, organization, name, attributes) VALUES (?, ?, ?, ?)
`

type InsertParams struct {
	Domain       string
	Organization string
	Name         string
	Attributes   string
}

func (q *Queries) Insert(ctx context.Context, arg InsertParams) error {
	_, err := q.db.ExecContext(ctx, insert,
		arg.Domain,
		arg.Organization,
		arg.Name,
		arg.Attributes,
	)
	return err
}

const search = `-- name: Search :many
SELECT domain, organization, name, attributes FROM entries where domain like ? AND organization like ? AND name like ?
`

type SearchParams struct {
	Domain       string
	Organization string
	Name         string
}

func (q *Queries) Search(ctx context.Context, arg SearchParams) ([]Entry, error) {
	rows, err := q.db.QueryContext(ctx, search, arg.Domain, arg.Organization, arg.Name)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var items []Entry
	for rows.Next() {
		var i Entry
		if err := rows.Scan(
			&i.Domain,
			&i.Organization,
			&i.Name,
			&i.Attributes,
		); err != nil {
			return nil, err
		}
		items = append(items, i)
	}
	if err := rows.Close(); err != nil {
		return nil, err
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

const update = `-- name: Update :exec
UPDATE entries SET attributes = ? WHERE domain = ? AND organization = ? AND name = ?
`

type UpdateParams struct {
	Attributes   string
	Domain       string
	Organization string
	Name         string
}

func (q *Queries) Update(ctx context.Context, arg UpdateParams) error {
	_, err := q.db.ExecContext(ctx, update,
		arg.Attributes,
		arg.Domain,
		arg.Organization,
		arg.Name,
	)
	return err
}
