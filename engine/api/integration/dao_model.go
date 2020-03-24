package integration

import (
	"context"
	"database/sql"

	"github.com/go-gorp/gorp"

	"github.com/ovh/cds/engine/api/database/gorpmapping"
	"github.com/ovh/cds/sdk"
	"github.com/ovh/cds/sdk/log"
)

// LoadModels load integration models
func LoadModels(db gorp.SqlExecutor) ([]sdk.IntegrationModel, error) {
	var pm integrationModelSlice

	query := gorpmapping.NewQuery(`SELECT * from integration_model`)
	if err := gorpmapping.GetAll(context.Background(), db, query, &pm, gorpmapping.GetOptions.WithDecryption); err != nil {
		return nil, err
	}

	res := pm.IntegrationModel() // This function checks the database signature
	for i := range res {
		res[i].Blur()
	}
	return res, nil
}

// LoadPublicModelsByType load integration models which are public
func LoadPublicModelsByType(db gorp.SqlExecutor, integrationType *sdk.IntegrationType, clearPassword bool) ([]sdk.IntegrationModel, error) {
	q := "SELECT * from integration_model WHERE public = true"
	if integrationType != nil {
		switch *integrationType {
		case sdk.IntegrationTypeEvent:
			q += " AND integration_model.event = true"
		case sdk.IntegrationTypeCompute:
			q += " AND integration_model.compute = true"
		case sdk.IntegrationTypeStorage:
			q += " AND integration_model.storage = true"
		case sdk.IntegrationTypeHook:
			q += " AND integration_model.hook = true"
		case sdk.IntegrationTypeDeployment:
			q += " AND integration_model.deployment = true"
		}
	}

	query := gorpmapping.NewQuery(q)
	var pm integrationModelSlice

	if err := gorpmapping.GetAll(context.Background(), db, query, &pm, gorpmapping.GetOptions.WithDecryption); err != nil {
		return nil, err
	}

	res := pm.IntegrationModel() // This function checks the database signature
	if !clearPassword {
		for i := range res {
			res[i].Blur()
		}
	}

	return res, nil
}

// LoadModel Load a integration model by its ID
func LoadModel(db gorp.SqlExecutor, modelID int64, clearPassword bool) (sdk.IntegrationModel, error) {
	query := gorpmapping.NewQuery("SELECT * from integration_model where id = $1").Args(modelID)
	var pm integrationModel

	found, err := gorpmapping.Get(context.Background(), db, query, &pm, gorpmapping.GetOptions.WithDecryption)
	if err != nil {
		return sdk.IntegrationModel{}, err
	}
	if !found {
		return sdk.IntegrationModel{}, sdk.WithStack(sdk.ErrNotFound)
	}

	isValid, err := gorpmapping.CheckSignature(pm, pm.Signature)
	if err != nil {
		return sdk.IntegrationModel{}, err
	}
	if !isValid {
		log.Error(context.Background(), "integration.LoadModel> model  %d data corrupted", pm.ID)
		return sdk.IntegrationModel{}, sdk.WithStack(sdk.ErrNotFound)
	}

	if !clearPassword {
		pm.Blur()
	}
	return pm.IntegrationModel, nil
}

// LoadModelByName Load a integration model by its name
func LoadModelByName(db gorp.SqlExecutor, name string, clearPassword bool) (sdk.IntegrationModel, error) {
	query := gorpmapping.NewQuery("SELECT * from integration_model where name = $1").Args(name)
	var pm integrationModel

	found, err := gorpmapping.Get(context.Background(), db, query, &pm, gorpmapping.GetOptions.WithDecryption)
	if err != nil {
		return sdk.IntegrationModel{}, err
	}
	if !found {
		return sdk.IntegrationModel{}, sdk.WithStack(sdk.ErrNotFound)
	}

	isValid, err := gorpmapping.CheckSignature(pm, pm.Signature)
	if err != nil {
		return sdk.IntegrationModel{}, err
	}
	if !isValid {
		log.Error(context.Background(), "integration.LoadModelByName> model  %d data corrupted", pm.ID)
		return sdk.IntegrationModel{}, sdk.WithStack(sdk.ErrNotFound)
	}

	if !clearPassword {
		pm.Blur()
	}
	return pm.IntegrationModel, nil
}

// ModelExists tests if the given model exists
func ModelExists(db gorp.SqlExecutor, name string) (bool, error) {
	var count = 0
	if err := db.QueryRow("select count(1) from integration_model where name = $1 GROUP BY id", name).Scan(&count); err != nil {
		if err == sql.ErrNoRows {
			return false, nil
		}
		return false, sdk.WrapError(err, "ModelExists")
	}
	return count > 0, nil
}

// InsertModel inserts a integration model in database
func InsertModel(db gorp.SqlExecutor, m *sdk.IntegrationModel) error {
	dbm := integrationModel{IntegrationModel: *m}
	if err := gorpmapping.InsertAndSign(context.Background(), db, &dbm); err != nil {
		return sdk.WrapError(err, "Unable to insert integration model %s", m.Name)
	}
	*m = dbm.IntegrationModel
	return nil
}

// UpdateModel updates a integration model in database
func UpdateModel(db gorp.SqlExecutor, m *sdk.IntegrationModel) error {
	dbm := integrationModel{IntegrationModel: *m}
	if err := gorpmapping.UpdateAndSign(context.Background(), db, &dbm); err != nil {
		return sdk.WrapError(err, "Unable to update integration model %s", m.Name)
	}
	return nil
}

// DeleteModel deletes a integration model in database
func DeleteModel(db gorp.SqlExecutor, id int64) error {
	m, err := LoadModel(db, id, false)
	if err != nil {
		return sdk.WrapError(err, "DeleteModel")
	}

	dbm := integrationModel{IntegrationModel: m}
	if _, err := db.Delete(&dbm); err != nil {
		return sdk.WrapError(err, "unable to delete model %s", m.Name)
	}

	return nil
}
