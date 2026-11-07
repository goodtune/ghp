package database

import (
	"context"
	"database/sql"
	"strings"
)

// promoteAdminsTx sets role='admin' on every user whose GitHub login matches
// an entry in adminUsernames under ASCII case folding (#334).
//
// SQL LOWER() on both sides is only a candidate pre-filter. The fold must
// never drop a pair that is equal under ASCII folding, so each backend
// supplies a fold expression that is ASCII-only:
//   - SQLite: built-in LOWER() folds ASCII letters only.
//   - Postgres: LOWER() follows the collation. Under a Turkish collation
//     (tr-x-icu, tr_TR) LOWER('IVAN') is 'ıvan', which would drop the true
//     match IVAN == ivan. The Postgres fold therefore applies COLLATE "C",
//     which lowercases ASCII letters only.
//
// The final decision is made in Go with
// asciiutil (via adminSet), the same rule the Vault backend and the
// in-process checks use. One query fetches the candidates for all entries,
// and the promotion runs by primary key inside the caller's transaction.
//
// placeholder returns the bind marker for the n-th (1-based) argument.
// fold wraps a SQL text expression in the backend's ASCII-only lowercase.
func promoteAdminsTx(ctx context.Context, tx *sql.Tx, adminUsernames []string, now any, placeholder func(n int) string, fold func(expr string) string) (err error) {
	if len(adminUsernames) == 0 {
		return nil
	}
	set := newAdminSet(adminUsernames)

	marks := make([]string, 0, len(set))
	args := make([]any, 0, len(set))
	for name := range set {
		args = append(args, name)
		marks = append(marks, fold(placeholder(len(args))))
	}
	rows, err := tx.QueryContext(ctx,
		`SELECT id, github_username FROM users WHERE `+fold("github_username")+` IN (`+strings.Join(marks, ", ")+`)`,
		args...,
	)
	if err != nil {
		return err
	}
	defer func() {
		if cerr := rows.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}()
	var ids []string
	for rows.Next() {
		var id, login string
		if err := rows.Scan(&id, &login); err != nil {
			return err
		}
		if set.has(login) {
			ids = append(ids, id)
		}
	}
	if err := rows.Err(); err != nil {
		return err
	}
	// Close before issuing updates on the same transaction.
	if err := rows.Close(); err != nil {
		return err
	}

	update := `UPDATE users SET role = 'admin', updated_at = ` + placeholder(1) + ` WHERE id = ` + placeholder(2)
	for _, id := range ids {
		if _, err := tx.ExecContext(ctx, update, now, id); err != nil {
			return err
		}
	}
	return nil
}
