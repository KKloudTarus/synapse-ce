package postgres

import (
	"testing"
)

// Startup migration is tested on a database upgraded from the immediately
// preceding embedded version; this catches goose version collisions as well.
func TestMigration0181UserContactsUpgrade(t *testing.T) {
	_,db:=ownershipTestDatabase(t,180,nil)
	for _,table:=range []string{"user_contacts","user_contact_challenges","user_contact_verification_requests"} {
		requireMigrationTable(t,db,table,true)
		requireMigrationRLS(t,db,table)
	}
	requireMigrationIndexes(t,db,"user_contacts_manual_value","user_contacts_oidc_source","user_contact_challenges_active","user_contact_verification_requests_recent")
}
