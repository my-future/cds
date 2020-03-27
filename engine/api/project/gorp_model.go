package project

import (
	"github.com/ovh/cds/engine/api/database/gorpmapping"
)

func init() {
	gorpmapping.Register(gorpmapping.New(dbProject{}, "project", true, "id"))
	gorpmapping.Register(gorpmapping.New(dbProjectVariableAudit{}, "project_variable_audit", true, "id"))
	gorpmapping.Register(gorpmapping.New(dbProjectKey{}, "project_key", true, "id"))
	gorpmapping.Register(gorpmapping.New(dbLabel{}, "project_label", true, "id"))
	gorpmapping.Register(gorpmapping.New(dbProjectVariable{}, "project_variable", true, "id"))
}
