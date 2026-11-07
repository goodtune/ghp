package database

import (
	"context"
	"database/sql"
	"strings"
)

// promoteAdminsTx sets role='admin' on every user whose GitHub login matches
// an entry in adminUsernames under ASCII case folding (#334).
//
// SQL LOWER() on both sides is only a candidate pre-filter: on Postgres it
// applies Unicode rules, so a Kelvin sign (U+212A) lowercases to "k" and a
// non-ASCII login could match an ASCII admin entry. Any pair equal under
// ASCII folding is also equal under SQL LOWER(), so the pre-filter never
// drops a true match. The final decision is made in Go with
// asciiutil (via adminSet), the same rule the Vault backend and the
// in-process checks use. One query fetches the candidates for all entries,
// and the promotion runs by primary key inside the caller's transaction.
//
// placeholder returns the bind marker for the n-th (1-based) argument.
func promoteAdminsTx(ctx context.Context, tx *sql.Tx, adminUsernames []string, now any, placeholder func(n int) string) error {
	if len(adminUsernames) == 0 {
		return nil
	}
	set := newAdminSet(adminUsernames)

	marks := make([]string, 0, len(set))
	args := make([]any, 0, len(set))
	for name := range set {
		args = append(args, name)
		marks = append(marks, "LOWER("+placeholder(len(args))+")")
	}
	rows, err := tx.QueryContext(ctx,
		`SELECT id, github_username FROM users WHERE LOWER(github_username) IN (`+strings.Join(marks, ", ")+`)`,
		args...,
	)
	if err != nil {
		return err
	}
	var ids []string
	for rows.Next() {
		var id, login string
		if err := rows.Scan(&id, &login); err != nil {
			rows.Close()
			return err
		}
		if set.has(login) {
			ids = append(ids, id)
		}
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
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
