// corpus: expect=PG-SQL-003
package store

import "database/sql"

func defaults() string {
	const tenantTable = "tenants_default"
	return tenantTable
}

// tenantTable is a package variable set from the request in middleware.go.
func ListTenants(db *sql.DB) (*sql.Rows, error) {
	return db.Query("SELECT * FROM " + tenantTable)
}
