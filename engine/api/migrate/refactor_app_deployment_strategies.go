package migrate

import (
	"context"
	"database/sql"
	"encoding/base64"
	"fmt"

	"github.com/go-gorp/gorp"
	"github.com/ovh/cds/engine/api/application"
	"github.com/ovh/cds/engine/api/database/gorpmapping"
	"github.com/ovh/cds/engine/api/secret"
	"github.com/ovh/cds/sdk"
	"github.com/ovh/cds/sdk/log"
)

func RefactorAppDeploymentStrategies(ctx context.Context, db *gorp.DbMap) error {
	query := `SELECT application_id, project_platform_id FROM application_deployment_strategy WHERE migrate IS NULL`
	rows, err := db.Query(query)
	if err == sql.ErrNoRows {
		return nil
	}
	if err != nil {
		return sdk.WithStack(err)
	}

	var ids = []struct{ appID, ppfID int64 }{}
	for rows.Next() {
		var appID, ppfID int64
		if err := rows.Scan(&appID, ppfID); err != nil {
			rows.Close() // nolint
			return sdk.WithStack(err)
		}
		ids = append(ids, struct{ appID, ppfID int64 }{appID, ppfID})
	}

	if err := rows.Close(); err != nil {
		return sdk.WithStack(err)
	}

	var mError = new(sdk.MultiError)
	for _, id := range ids {
		if err := refactorAppDeploymentStrategies(ctx, db, id.appID, id.ppfID); err != nil {
			mError.Append(err)
			log.Error(ctx, "migrate.refactorAppDeploymentStrategies> unable to migrate application_deployment_strategy %d: %v", id, err)
		}
	}

	if mError.IsEmpty() {
		return nil
	}
	return mError
}

func refactorAppDeploymentStrategies(ctx context.Context, db *gorp.DbMap, appID, ppfID int64) error {
	tx, err := db.Begin()
	if err != nil {
		return sdk.WithStack(err)
	}

	defer tx.Rollback() // nolint

	query := `
	SELECT 
		project_integration.project_id, 
		project_integration.integration_model_id, 
		project_integration.name, 
		application_deployment_strategy.config
	FROM application_deployment_strategy
	JOIN project_integration ON project_integration.id = application_deployment_strategy.project_integration_id
	JOIN integration_model ON integration_model.id = project_integration.integration_model_id
	WHERE application_deployment_strategy.application_id = $1
	AND application_deployment_strategy.project_platform_id = $2
	AND application_deployment_strategy.migrate is NULL
	FOR UPDATE SKIP LOCKED`

	res := struct {
		ProjID int64          `db:"project_id"`
		PfID   int64          `db:"integration_model_id"`
		Name   string         `db:"name"`
		Config sql.NullString `db:"config"`
	}{}

	if err := tx.SelectOne(&res, query, appID, ppfID); err != nil {
		return sdk.WrapError(err, "unable to load deployment strategies")
	}

	cfg := sdk.IntegrationConfig{}
	if err := gorpmapping.JSONNullString(res.Config, &cfg); err != nil {
		return sdk.WrapError(err, "unable to parse config")
	}
	//Parse the config and replace password values
	newCfg := sdk.IntegrationConfig{}
	for k, v := range cfg {
		if v.Type == sdk.IntegrationConfigTypePassword {
			s, err := base64.StdEncoding.DecodeString(v.Value)
			if err != nil {
				return sdk.WrapError(err, "unable to decode encrypted value")
			}
			decryptedValue, err := secret.Decrypt([]byte(s))
			if err != nil {
				return sdk.WrapError(err, "unable to decrypt secret value")
			}
			newCfg[k] = sdk.IntegrationConfigValue{
				Type:  sdk.IntegrationConfigTypePassword,
				Value: string(decryptedValue),
			}
		} else {
			newCfg[k] = v
		}
	}

	if err := application.SetDeploymentStrategy(tx, res.ProjID, appID, res.PfID, res.Name, newCfg); err != nil {
		return err
	}

	query = `UPDATE application_deployment_strategy
	SET migrate = true
	WHERE application_id = $1
	AND project_platform_id = $2`
	r, err := tx.Exec(query)
	if err != nil {
		return sdk.WithStack(err)
	}

	if n, _ := r.RowsAffected(); n != 1 {
		return sdk.WithStack(fmt.Errorf("%d lines affected... error", n))
	}

	log.Info(ctx, "migrate.refactorAppDeploymentStrategies> config %s (%d) migrated", res.Name, appID)

	if err := tx.Commit(); err != nil {
		return err
	}

	return nil
}
