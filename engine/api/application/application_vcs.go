package application

import (
	"github.com/ovh/cds/engine/api/database/gorpmapping"

	"github.com/go-gorp/gorp"

	"github.com/ovh/cds/sdk"
)

// EncryptVCSStrategyPassword Encrypt vcs password
func EncryptVCSStrategyPassword(app *sdk.Application) error {
	var encryptedPwd []byte
	if err := gorpmapping.Encrypt(app.RepositoryStrategy.Password, &encryptedPwd, []interface{}{app.ProjectKey, app.ID}); err != nil {
		return sdk.WrapError(err, "Unable to encrypt password")
	}

	app.RepositoryStrategy.Password = string(encryptedPwd)
	return nil
}

// DecryptVCSStrategyPassword Decrypt vs password
func DecryptVCSStrategyPassword(app *sdk.Application) error {
	if app.RepositoryStrategy.Password == "" {
		return nil
	}

	var clearPWD string
	if err := gorpmapping.Decrypt([]byte(app.RepositoryStrategy.Password), &clearPWD, []interface{}{app.ProjectKey, app.ID}); err != nil {
		return err
	}

	app.RepositoryStrategy.Password = clearPWD
	return nil
}

// CountApplicationByVcsConfigurationKeys counts key use in application vcs configuration for the given project
func CountApplicationByVcsConfigurationKeys(db gorp.SqlExecutor, projectKey string, vcsName string) ([]string, error) {
	query := `
		SELECT prequery.name FROM 
		(
			SELECT application.name, vcs_strategy->>'ssh_key' as sshkey, vcs_strategy->>'pgp_key' as pgpkey from application
			JOIN project on application.project_id = project.id
			WHERE project.projectkey = $1
		) prequery
		WHERE sshkey = $2 OR pgpkey = $2`
	var appsName []string
	if _, err := db.Select(&appsName, query, projectKey, vcsName); err != nil {
		return nil, sdk.WrapError(err, "Cannot count keyName in vcs configuration")
	}
	return appsName, nil
}

// GetNameByVCSServer Get the name of application that are linked to the given repository manager
func GetNameByVCSServer(db gorp.SqlExecutor, vcsName string, projectKey string) ([]string, error) {
	var appsName []string
	query := `
		SELECT application.name
		FROM application
		JOIN project on project.id = application.project_id
		WHERE project.projectkey = $1 AND application.vcs_server = $2
	`
	if _, err := db.Select(&appsName, query, projectKey, vcsName); err != nil {
		return nil, sdk.WrapError(err, "Unable to list application name")
	}
	return appsName, nil
}
