// corpus: expect=PG-SQL-003
package store

import (
	"context"
	"database/sql"
	"fmt"
)

func Find(ctx context.Context, db *sql.DB, email string) (*sql.Rows, error) {
	query := fmt.Sprintf("SELECT id FROM users WHERE email = '%s'", email)
	return db.QueryContext(ctx, query)
}
