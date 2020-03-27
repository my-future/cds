package project

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"time"

	"github.com/go-gorp/gorp"

	"github.com/ovh/cds/engine/api/database/gorpmapping"
	"github.com/ovh/cds/sdk"
	"github.com/ovh/cds/sdk/log"
)

type dbProjectVariableAudit sdk.ProjectVariableAudit

type dbProjectVariable struct {
	gorpmapping.SignedEntity
	ID          int64  `db:"id"`
	ProjectID   int64  `db:"project_id"`
	Name        string `db:"var_name"`
	ClearValue  string `db:"var_value"`
	CipherValue string `db:"cipher_value" gorpmapping:"encrypted,ID,Name"`
	Type        string `db:"var_type"`
}

func (e dbProjectVariable) Canonical() gorpmapping.CanonicalForms {
	var _ = []interface{}{e.ProjectID, e.ID, e.Name, e.Type}
	return gorpmapping.CanonicalForms{
		"{{print .ProjectID}}{{print .ID}}{{.Name}}{{.Type}}",
	}
}

func newDBProjectVariable(v sdk.Variable, projID int64) dbProjectVariable {
	if sdk.NeedPlaceholder(v.Type) {
		return dbProjectVariable{
			ID:          v.ID,
			Name:        v.Name,
			CipherValue: v.Value,
			Type:        v.Type,
			ProjectID:   projID,
		}
	}
	return dbProjectVariable{
		ID:         v.ID,
		Name:       v.Name,
		ClearValue: v.Value,
		Type:       v.Type,
		ProjectID:  projID,
	}
}

func (e dbProjectVariable) Variable() sdk.Variable {
	if sdk.NeedPlaceholder(e.Type) {
		return sdk.Variable{
			ID:    e.ID,
			Name:  e.Name,
			Value: e.CipherValue,
			Type:  e.Type,
		}
	}

	return sdk.Variable{
		ID:    e.ID,
		Name:  e.Name,
		Value: e.ClearValue,
		Type:  e.Type,
	}
}

func loadAllVariables(db gorp.SqlExecutor, query gorpmapping.Query, opts ...gorpmapping.GetOptionFunc) ([]sdk.Variable, error) {
	var ctx = context.Background()
	var res []dbProjectVariable
	vars := make([]sdk.Variable, 0, len(res))

	if err := gorpmapping.GetAll(ctx, db, query, &res, opts...); err != nil {
		return nil, err
	}

	for i := range res {
		isValid, err := gorpmapping.CheckSignature(res[i], res[i].Signature)
		if err != nil {
			return nil, err
		}
		if !isValid {
			log.Error(ctx, "project.getAllVariables> project key %d data corrupted", res[i].ID)
			continue
		}
		vars = append(vars, res[i].Variable())
	}
	return vars, nil
}

// LoadAllVariables Get all variable for the given project
func LoadAllVariables(db gorp.SqlExecutor, projID int64) ([]sdk.Variable, error) {
	query := gorpmapping.NewQuery(`
		SELECT *
		FROM project_variable
		WHERE project_id = $1
		ORDER BY var_name
			  `).Args(projID)
	return loadAllVariables(db, query)
}

// LoadAllVariablesWithDecrytion Get all variable for the given project, it also decrypt all the secure content
func LoadAllVariablesWithDecrytion(db gorp.SqlExecutor, projID int64) ([]sdk.Variable, error) {
	query := gorpmapping.NewQuery(`
		SELECT *
		FROM project_variable
		WHERE project_id = $1
		ORDER BY var_name
			  `).Args(projID)
	return loadAllVariables(db, query, gorpmapping.GetOptions.WithDecryption)
}

func loadVariable(db gorp.SqlExecutor, q gorpmapping.Query, opts ...gorpmapping.GetOptionFunc) (*sdk.Variable, error) {
	var v dbProjectVariable
	found, err := gorpmapping.Get(context.Background(), db, q, &v, opts...)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, sdk.WithStack(sdk.ErrNotFound)
	}
	isValid, err := gorpmapping.CheckSignature(v, v.Signature)
	if err != nil {
		return nil, err
	}
	if !isValid {
		log.Error(context.Background(), "project.loadVariable> project variable %d data corrupted", v.ID)
		return nil, sdk.WithStack(sdk.ErrNotFound)
	}

	res := v.Variable()
	return &res, err
}

// LoadVariable retrieve a specific variable
func LoadVariable(db gorp.SqlExecutor, projID int64, varName string) (*sdk.Variable, error) {
	query := gorpmapping.NewQuery(`SELECT * FROM project_variable
			WHERE project_id = $1 AND var_name=$2`).Args(projID, varName)
	return loadVariable(db, query)
}

// LoadVariableWithDecryption retrieve a specific variable with decrypted content
func LoadVariableWithDecryption(db gorp.SqlExecutor, projID int64, varID int64, varName string) (*sdk.Variable, error) {
	query := gorpmapping.NewQuery(`SELECT * FROM project_variable
			WHERE project_id = $1 AND id = $2 AND var_name=$3`).Args(projID, varID, varName)
	return loadVariable(db, query, gorpmapping.GetOptions.WithDecryption)
}

// DeleteAllVariables Delete all variables from the given project.
func DeleteAllVariables(db gorp.SqlExecutor, projectID int64) error {
	query := `DELETE FROM project_variable
	          WHERE project_variable.project_id = $1`
	if _, err := db.Exec(query, projectID); err != nil {
		return sdk.WithStack(err)
	}
	return nil
}

// InsertVariable Insert a new variable in the given project
func InsertVariable(db gorp.SqlExecutor, projID int64, v *sdk.Variable, u sdk.Identifiable) error {
	//Check variable name
	rx := sdk.NamePatternRegex
	if !rx.MatchString(v.Name) {
		return sdk.NewError(sdk.ErrInvalidName, fmt.Errorf("Invalid variable name. It should match %s", sdk.NamePattern))
	}

	if sdk.NeedPlaceholder(v.Type) && v.Value == sdk.PasswordPlaceholder {
		return fmt.Errorf("You try to insert a placeholder for new variable %s", v.Name)
	}

	dbVar := newDBProjectVariable(*v, projID)
	if err := gorpmapping.InsertAndSign(context.Background(), db, &dbVar); err != nil {
		return sdk.WrapError(err, "Cannot insert variable %s", v.Name)
	}

	*v = dbVar.Variable()

	ava := &sdk.ProjectVariableAudit{
		ProjectID:     projID,
		Type:          sdk.AuditAdd,
		Author:        u.GetUsername(),
		VariableAfter: *v,
		VariableID:    v.ID,
		Versionned:    time.Now(),
	}

	if err := insertAudit(db, ava); err != nil {
		return sdk.WrapError(err, "Cannot insert audit for variable %d", v.ID)
	}
	return nil
}

// UpdateVariable Update a variable in the given project
func UpdateVariable(db gorp.SqlExecutor, projID int64, variable *sdk.Variable, variableBefore *sdk.Variable, u sdk.Identifiable) error {
	rx := sdk.NamePatternRegex
	if !rx.MatchString(variable.Name) {
		return sdk.NewError(sdk.ErrInvalidName, fmt.Errorf("Invalid variable name. It should match %s", sdk.NamePattern))
	}

	dbVar := newDBProjectVariable(*variable, projID)

	if err := gorpmapping.UpdateAndSign(context.Background(), db, &dbVar); err != nil {
		return err
	}

	*variable = dbVar.Variable()

	if variableBefore == nil && u == nil {
		return nil
	}

	ava := &sdk.ProjectVariableAudit{
		ProjectID:      projID,
		Type:           sdk.AuditUpdate,
		Author:         u.GetUsername(),
		VariableAfter:  *variable,
		VariableBefore: variableBefore,
		VariableID:     variable.ID,
		Versionned:     time.Now(),
	}

	if err := insertAudit(db, ava); err != nil {
		return sdk.WrapError(err, "Cannot insert audit for variable %s", variable.Name)
	}

	return nil
}

// DeleteVariable Delete a variable from the given pipeline
func DeleteVariable(db gorp.SqlExecutor, projID int64, variable *sdk.Variable, u sdk.Identifiable) error {
	query := `DELETE FROM project_variable
		  WHERE project_variable.project_id = $1 AND project_variable.var_name = $2`
	result, err := db.Exec(query, projID, variable.Name)
	if err != nil {
		return sdk.WrapError(err, "Cannot delete variable %s", variable.Name)
	}

	rowAffected, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if rowAffected == 0 {
		return sdk.ErrNotFound
	}

	ava := &sdk.ProjectVariableAudit{
		ProjectID:      projID,
		Type:           sdk.AuditDelete,
		Author:         u.GetUsername(),
		VariableBefore: variable,
		VariableID:     variable.ID,
		Versionned:     time.Now(),
	}

	if err := insertAudit(db, ava); err != nil {
		return sdk.WrapError(err, "Cannot insert audit for variable %s", variable.Name)
	}
	return nil
}

// PostGet is a db hook
func (pva *dbProjectVariableAudit) PostGet(db gorp.SqlExecutor) error {
	var before, after sql.NullString
	query := "SELECT variable_before, variable_after from project_variable_audit WHERE id = $1"
	if err := db.QueryRow(query, pva.ID).Scan(&before, &after); err != nil {
		return err
	}

	if before.Valid {
		vBefore := &sdk.Variable{}
		if err := json.Unmarshal([]byte(before.String), vBefore); err != nil {
			return err
		}
		if sdk.NeedPlaceholder(vBefore.Type) {
			vBefore.Value = sdk.PasswordPlaceholder
		}
		pva.VariableBefore = vBefore

	}

	if after.Valid {
		vAfter := &sdk.Variable{}
		if err := json.Unmarshal([]byte(after.String), vAfter); err != nil {
			return err
		}
		if sdk.NeedPlaceholder(vAfter.Type) {
			vAfter.Value = sdk.PasswordPlaceholder
		}
		pva.VariableAfter = *vAfter
	}

	return nil
}

// PostUpdate is a db hook
func (pva *dbProjectVariableAudit) PostUpdate(db gorp.SqlExecutor) error {
	var vB, vA sql.NullString

	if pva.VariableBefore != nil {
		v, err := json.Marshal(pva.VariableBefore)
		if err != nil {
			return err
		}
		vB.Valid = true
		vB.String = string(v)
	}

	v, err := json.Marshal(pva.VariableAfter)
	if err != nil {
		return err
	}
	vA.Valid = true
	vA.String = string(v)

	query := "update project_variable_audit set variable_before = $2, variable_after = $3 where id = $1"
	if _, err := db.Exec(query, pva.ID, vB, vA); err != nil {
		return err
	}
	return nil
}

// PostInsert is a db hook
func (pva *dbProjectVariableAudit) PostInsert(db gorp.SqlExecutor) error {
	return pva.PostUpdate(db)
}

// PreInsert
func (pva *dbProjectVariableAudit) PreInsert(s gorp.SqlExecutor) error {
	if pva.VariableBefore != nil {
		if sdk.NeedPlaceholder(pva.VariableBefore.Type) {
			pva.VariableBefore.Value = sdk.PasswordPlaceholder
		}
	}
	if sdk.NeedPlaceholder(pva.VariableAfter.Type) {
		pva.VariableAfter.Value = sdk.PasswordPlaceholder
	}

	return nil
}
