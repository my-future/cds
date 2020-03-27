package project

import (
	"context"
	"database/sql"
	"time"

	"github.com/go-gorp/gorp"

	"github.com/ovh/cds/engine/api/cache"
	"github.com/ovh/cds/engine/api/database/gorpmapping"
	"github.com/ovh/cds/engine/api/environment"
	"github.com/ovh/cds/engine/api/group"
	"github.com/ovh/cds/engine/api/keys"
	"github.com/ovh/cds/sdk"
	"github.com/ovh/cds/sdk/log"
)

type dbProject struct {
	gorpmapping.SignedEntity
	sdk.Project
}

func (e dbProject) Canonical() gorpmapping.CanonicalForms {
	var _ = []interface{}{e.ID, e.Key}
	return gorpmapping.CanonicalForms{
		"{{print .ID}}{{.Key}}",
	}
}

func loadAllByRepo(ctx context.Context, db gorp.SqlExecutor, store cache.Store, query gorpmapping.Query, opts ...LoadOptionFunc) (sdk.Projects, error) {
	return loadprojects(ctx, db, store, opts, query)
}

// LoadAllByRepoAndGroupIDs returns all projects with an application linked to the repo against the groups
func LoadAllByRepoAndGroupIDs(ctx context.Context, db gorp.SqlExecutor, store cache.Store, groupIDs []int64, repo string, opts ...LoadOptionFunc) (sdk.Projects, error) {
	queryStr := `SELECT DISTINCT project.*
		FROM  project
		JOIN  application on project.id = application.project_id
		WHERE application.repo_fullname = $3
		AND   project.id IN (
			SELECT project_group.project_id
			FROM project_group
			WHERE
				project_group.group_id = ANY(string_to_array($1, ',')::int[])
				OR
				$2 = ANY(string_to_array($1, ',')::int[])
		)`
	query := gorpmapping.NewQuery(queryStr).Args(gorpmapping.IDsToQueryString(groupIDs), group.SharedInfraGroup.ID, repo)
	return loadAllByRepo(ctx, db, store, query, opts...)
}

// LoadAllByRepo returns all projects with an application linked to the repo
func LoadAllByRepo(ctx context.Context, db gorp.SqlExecutor, store cache.Store, repo string, opts ...LoadOptionFunc) (sdk.Projects, error) {
	queryStr := `SELECT DISTINCT project.*
	FROM  project
	JOIN  application on project.id = application.project_id
	WHERE application.repo_fullname = $1
	ORDER by project.name, project.projectkey ASC`
	query := gorpmapping.NewQuery(queryStr).Args(repo)
	return loadAllByRepo(ctx, db, store, query, opts...)
}

// LoadAllByGroupIDs returns all projects given groups
func LoadAllByGroupIDs(ctx context.Context, db gorp.SqlExecutor, store cache.Store, IDs []int64, opts ...LoadOptionFunc) (sdk.Projects, error) {
	queryStr := `SELECT project.*
	FROM project
	WHERE project.id IN (
		SELECT project_group.project_id
		FROM project_group
		WHERE
			project_group.group_id = ANY(string_to_array($1, ',')::int[])
			OR
			$2 = ANY(string_to_array($1, ',')::int[])
	)
	ORDER by project.name, project.projectkey ASC`
	query := gorpmapping.NewQuery(queryStr).Args(gorpmapping.IDsToQueryString(IDs), group.SharedInfraGroup.ID)
	return loadprojects(ctx, db, store, opts, query)
}

// LoadAll returns all projects
func LoadAll(ctx context.Context, db gorp.SqlExecutor, store cache.Store, opts ...LoadOptionFunc) (sdk.Projects, error) {
	queryStr := "select project.* from project ORDER by project.name, project.projectkey ASC"
	query := gorpmapping.NewQuery(queryStr)
	return loadprojects(ctx, db, store, opts, query)
}

// Delete delete one or more projects given the key
func Delete(db gorp.SqlExecutor, store cache.Store, key string) error {
	proj, err := Load(db, store, key, nil)
	if err != nil {
		return err
	}

	return DeleteByID(db, proj.ID)
}

// BuiltinGPGKey is a const
const BuiltinGPGKey = "builtin"

// Insert a new project in database
func Insert(db gorp.SqlExecutor, store cache.Store, proj *sdk.Project) error {
	if err := proj.IsValid(); err != nil {
		return sdk.WrapError(err, "project is not valid")
	}

	proj.LastModified = time.Now()
	dbProj := dbProject{Project: *proj}
	if err := gorpmapping.InsertAndSign(context.Background(), db, &dbProj); err != nil {
		return err
	}

	*proj = dbProj.Project
	proj.Blur() // Mask any sensitive data

	k, err := keys.GeneratePGPKeyPair(BuiltinGPGKey)
	if err != nil {
		return sdk.WrapError(err, "Unable to generate PGPKeyPair: %v", err)
	}

	pk := sdk.ProjectKey{}
	pk.KeyID = k.KeyID
	pk.Name = BuiltinGPGKey
	pk.Private = k.Private
	pk.Public = k.Public
	pk.Type = sdk.KeyTypePGP
	pk.ProjectID = proj.ID
	pk.Builtin = true

	if err := InsertKey(db, &pk); err != nil {
		return sdk.WrapError(err, "Unable to insert PGPKeyPair")
	}

	return nil
}

// Update a new project in database
func Update(db gorp.SqlExecutor, store cache.Store, proj *sdk.Project) error {
	if err := proj.IsValid(); err != nil {
		return sdk.WrapError(err, "project is not valid")
	}

	proj.LastModified = time.Now()

	dbProj := dbProject{Project: *proj}
	copyOfVCSServer := proj.VCSServers
	if err := gorpmapping.UpdateAndSign(context.Background(), db, &dbProj); err != nil {
		return err
	}

	*proj = dbProj.Project
	proj.VCSServers = copyOfVCSServer
	proj.Blur() // Mask any sensitive data

	return nil
}

// DeleteByID removes given project from database (project and project_group table)
// DeleteByID also removes all pipelines inside project (pipeline and pipeline_group table).
func DeleteByID(db gorp.SqlExecutor, id int64) error {
	if err := DeleteAllVariables(db, id); err != nil {
		return err
	}

	if err := environment.DeleteAllEnvironment(db, id); err != nil {
		return err
	}

	if _, err := db.Exec(`DELETE FROM repositories_manager_project WHERE id_project = $1`, id); err != nil {
		return err
	}

	if _, err := db.Exec(`DELETE FROM project WHERE project.id = $1`, id); err != nil {
		return err
	}
	return nil
}

// LoadProjectByNodeJobRunID return a project from node job run id
func LoadProjectByNodeJobRunID(ctx context.Context, db gorp.SqlExecutor, store cache.Store, nodeJobRunID int64, opts ...LoadOptionFunc) (*sdk.Project, error) {
	queryStr := `SELECT project.* 
	FROM project
	JOIN workflow_run ON workflow_run.project_id = project.id
	JOIN workflow_node_run ON workflow_node_run.workflow_run_id = workflow_run.id
	JOIN workflow_node_run_job ON workflow_node_run_job.workflow_node_run_id = workflow_node_run.id
	WHERE workflow_node_run_job.id = $1`
	query := gorpmapping.NewQuery(queryStr).Args(nodeJobRunID)
	return load(ctx, db, store, opts, query)
}

// LoadByID returns a project with all its variables and applications given a user. It can also returns pipelines, environments, groups, permission, and repositorires manager. See LoadOptions
func LoadByID(db gorp.SqlExecutor, store cache.Store, id int64, opts ...LoadOptionFunc) (*sdk.Project, error) {
	queryStr := "SELECT project.* FROM project WHERE id = $1"
	query := gorpmapping.NewQuery(queryStr).Args(id)
	return load(context.TODO(), db, store, opts, query)
}

// Load  returns a project with all its variables and applications given a user. It can also returns pipelines, environments, groups, permission, and repositorires manager. See LoadOptions
func Load(db gorp.SqlExecutor, store cache.Store, key string, opts ...LoadOptionFunc) (*sdk.Project, error) {
	queryStr := "SELECT project.* FROM project WHERE projectkey = $1"
	query := gorpmapping.NewQuery(queryStr).Args(key)
	return load(nil, db, store, opts, query)
}

// LoadProjectByWorkflowID loads a project from workflow iD
func LoadProjectByWorkflowID(db gorp.SqlExecutor, store cache.Store, workflowID int64, opts ...LoadOptionFunc) (*sdk.Project, error) {
	queryStr := `SELECT project.*
	FROM project
	JOIN workflow ON workflow.project_id = project.id
	WHERE workflow.id = $1 `
	query := gorpmapping.NewQuery(queryStr).Args(workflowID)
	return load(context.TODO(), db, store, opts, query)
}

func loadprojects(ctx context.Context, db gorp.SqlExecutor, store cache.Store, opts []LoadOptionFunc, query gorpmapping.Query) ([]sdk.Project, error) {
	var res []dbProject
	if err := gorpmapping.GetAll(ctx, db, query, &res, gorpmapping.GetOptions.WithDecryption); err != nil {
		return nil, err
	}
	projs := make([]sdk.Project, 0, len(res))
	for i := range res {
		p := &res[i]
		proj, err := unwrap(db, store, p, opts)
		if err != nil {
			log.Error(ctx, "loadprojects> unwrap error (ID=%d, Key:%s): %v", p.ID, p.Key, err)
			continue
		}
		projs = append(projs, *proj)
	}

	return projs, nil
}

func unsafeLoad(ctx context.Context, db gorp.SqlExecutor, query gorpmapping.Query) (*dbProject, error) {
	var dbProj dbProject
	found, err := gorpmapping.Get(ctx, db, query, &dbProj, gorpmapping.GetOptions.WithDecryption)
	if err != nil {
		return nil, sdk.WithStack(err)
	}
	if !found {
		return nil, sdk.WithStack(sdk.ErrNotFound)
	}
	return &dbProj, nil
}

func load(ctx context.Context, db gorp.SqlExecutor, store cache.Store, opts []LoadOptionFunc, query gorpmapping.Query) (*sdk.Project, error) {
	dbProj, err := unsafeLoad(ctx, db, query)
	if err != nil {
		return nil, err
	}

	isValid, err := gorpmapping.CheckSignature(dbProj, dbProj.Signature)
	if err != nil {
		return nil, err
	}
	if !isValid {
		log.Error(context.Background(), "project.load> project %d data corrupted", dbProj.ID)
		return nil, sdk.WithStack(sdk.ErrNotFound)
	}
	return unwrap(db, store, dbProj, opts)
}

func unwrap(db gorp.SqlExecutor, store cache.Store, p *dbProject, opts []LoadOptionFunc) (*sdk.Project, error) {
	proj := p.Project
	for _, f := range opts {
		if f == nil {
			continue
		}
		if err := f(db, store, &proj); err != nil && sdk.Cause(err) != sql.ErrNoRows {
			return nil, err
		}
	}
	proj.Blur() // Mask any sensitive data
	return &proj, nil
}

// UpdateFavorite add or delete project from user favorites
func UpdateFavorite(db gorp.SqlExecutor, projectID int64, userID string, add bool) error {
	var query string
	if add {
		query = "INSERT INTO project_favorite (authentified_user_id, project_id) VALUES ($1, $2)"
	} else {
		query = "DELETE FROM project_favorite WHERE authentified_user_id = $1 AND project_id = $2"
	}
	_, err := db.Exec(query, userID, projectID)
	return sdk.WithStack(err)
}

func daoVCSServerColumnFilter(col *gorp.ColumnMap) bool {
	return col.ColumnName == "cipher_vcs_servers"
}

func AddVCSServer(db gorp.SqlExecutor, proj *sdk.Project, vcsServer *sdk.ProjectVCSServer) error {
	servers, err := LoadAllVCSServersWithClearContent(db, proj.Key)
	for _, server := range servers {
		if server.Name == vcsServer.Name {
			return sdk.WithStack(sdk.ErrConflict)
		}
	}
	if err != nil {
		return err
	}

	servers = append(servers, *vcsServer)

	proj.VCSServers = servers
	dbProj := dbProject{Project: *proj}
	if err := gorpmapping.UpdateColumns(db, dbProj, daoVCSServerColumnFilter); err != nil {
		return err
	}
	proj.Blur()
	return nil
}

func UpdateVCSServer(db gorp.SqlExecutor, proj *sdk.Project, vcsServers *sdk.ProjectVCSServer) error {
	servers, err := LoadAllVCSServersWithClearContent(db, proj.Key)
	if err != nil {
		return err
	}

	var vcsSrv *sdk.ProjectVCSServer
	for i := range servers {
		if servers[i].Name == vcsServer.Name {
			vcsSrv = &servers[i]
		}
	}

	if vcsSrv == nil {
		return sdk.WithStack(sdk.ErrNotFound)
	}

	*vcsSrv = *vcsServers

	proj.VCSServers = vcsServers
	dbProj := dbProject{Project: *proj}
	if err := gorpmapping.UpdateColumns(db, dbProj, daoVCSServerColumnFilter); err != nil {
		return err
	}
	proj.Blur()
	return nil
}

func RemoveVCSServer(db gorp.SqlExecutor, proj *sdk.Project, vcsServer *sdk.ProjectVCSServer) error {
	servers, err := LoadAllVCSServersWithClearContent(db, proj.Key)
	if err != nil {
		return err
	}

	for i := range servers {
		if servers[i].Name == vcsServer.Name {
			servers = append(servers[:i], servers[i+1:]...)
			break
		}
	}

	proj.VCSServers = servers
	dbProj := dbProject{Project: *proj}
	if err := gorpmapping.UpdateColumns(db, dbProj, daoVCSServerColumnFilter); err != nil {
		return err
	}
	proj.Blur()
	return nil

}

func LoadAllVCSServersWithClearContent(db gorp.SqlExecutor, projectKey string) ([]sdk.ProjectVCSServer, error) {
	query := gorpmapping.NewQuery("select * from project where projectkey $ $1").Args(projectKey)
	// It is fine to do only unsafeLoad because the cipher column cipher_vcs_servers is cryptographically
	// authentified by the same piece of data than the project signature
	dbProj, err := unsafeLoad(context.Background(), db, query)
	if err != nil {
		return nil, err
	}
	return dbProj.VCSServers, nil
}

func LoadVCSServerWithClearContent(db gorp.SqlExecutor, projectKey, rmName string) (*sdk.ProjectVCSServer, error) {
	vcsServers, err := LoadAllVCSServersWithClearContent(db, projectKey)
	if err != nil {
		return nil, err
	}
	for _, v := range vcsServers {
		if v.Name == rmName {
			return &v, nil
		}
	}
	return nil, sdk.WithStack(sdk.ErrNotFound)
}
