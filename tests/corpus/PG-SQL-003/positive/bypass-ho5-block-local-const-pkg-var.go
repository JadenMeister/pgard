// corpus: expect=PG-SQL-003
package store

import "database/sql"

// reportTable is a package variable assigned from tenant settings in settings.go.
func Report(db *sql.DB, preview bool) (*sql.Rows, error) {
	if preview {
		const reportTable = "report_preview"
		return db.Query("SELECT * FROM " + reportTable)
	}
	return db.Query("SELECT * FROM " + reportTable)
}
