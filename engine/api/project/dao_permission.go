package project

import (
	"time"

	"github.com/go-gorp/gorp"
	"github.com/ovh/cds/sdk"
)

// LoadPermissions loads all projects where group has access
func LoadPermissions(db gorp.SqlExecutor, groupID int64) ([]sdk.ProjectGroup, error) {
	res := []sdk.ProjectGroup{}
	query := `
		SELECT project.projectKey, project.name, project.last_modified, project_group.role
		FROM project
	 	JOIN project_group ON project_group.project_id = project.id
	 	WHERE project_group.group_id = $1
		ORDER BY project.name ASC`

	rows, err := db.Query(query, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	for rows.Next() {
		var projectKey, projectName string
		var perm int
		var lastModified time.Time
		if err := rows.Scan(&projectKey, &projectName, &lastModified, &perm); err != nil {
			return nil, err
		}
		res = append(res, sdk.ProjectGroup{
			Project: sdk.Project{
				Key:          projectKey,
				Name:         projectName,
				LastModified: lastModified,
			},
			Permission: perm,
		})
	}
	return res, nil
}
