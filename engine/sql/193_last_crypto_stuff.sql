-- +migrate Up

-- RefactorAppDeploymentStrategies
CREATE TABLE application_deployment_strategy_tmp AS SELECT * FROM application_deployment_strategy;
ALTER TABLE application_deployment_strategy_tmp ADD PRIMARY KEY (application_id, project_platform_id);
ALTER TABLE "application_deployment_strategy" ADD COLUMN IF NOT EXISTS migrate BOOLEAN;

-- RefactorProjectIntegration
CREATE TABLE project_integration_tmp AS SELECT * FROM project_integration;
ALTER TABLE project_integration_tmp ADD PRIMARY KEY (id);
ALTER TABLE "project_integration" ADD COLUMN IF NOT EXISTS migrate BOOLEAN;

-- RefactorWorkerModel
CREATE TABLE worker_model_tmp AS SELECT * FROM worker_model;
ALTER TABLE worker_model_tmp ADD PRIMARY KEY (id);
ALTER TABLE "worker_model" ADD COLUMN IF NOT EXISTS migrate BOOLEAN;

-- RefactorProjectVCS
CREATE TABLE project_tmp AS SELECT * FROM project;
ALTER TABLE project_tmp ADD PRIMARY KEY (id);
ALTER TABLE "project" ADD COLUMN IF NOT EXISTS migrate BOOLEAN;

-- RefactorApplicationVCS
CREATE TABLE application_tmp AS SELECT * FROM "application";
ALTER TABLE application_tmp ADD PRIMARY KEY (id);
ALTER TABLE "application" ADD COLUMN IF NOT EXISTS migrate BOOLEAN;

-- RefactorIntegrationModel
CREATE TABLE integration_model_tmp AS SELECT * FROM integration_model;
ALTER TABLE integration_model_tmp ADD PRIMARY KEY (id);
ALTER TABLE "integration_model" ADD COLUMN IF NOT EXISTS migrate BOOLEAN;

-- +migrate Down

ALTER TABLE "application_deployment_strategy" DROP COLUMN migrate;
UPDATE  application_deployment_strategy 
SET     config = application_deployment_strategy_tmp.config
FROM    application_deployment_strategy_tmp
WHERE   application_deployment_strategy_tmp.application_id = application_deployment_strategy.application_id
AND     application_deployment_strategy_tmp.project_platform_id = application_deployment_strategy.project_platform_id;
DROP TABLE application_deployment_strategy_tmp;

ALTER TABLE "project_integration" DROP COLUMN migrate;
UPDATE  project_integration 
SET     config = project_integration_tmp.config
FROM    application_deployment_strategy_tmp
WHERE   project_integration_tmp.id = project_integration.id
DROP TABLE project_integration_tmp;

ALTER TABLE "worker_model" DROP COLUMN migrate;
UPDATE  worker_model 
SET     model = worker_model_tmp.config
FROM    worker_model_tmp
WHERE   worker_model_tmp.id = worker_model.id
DROP TABLE worker_model_tmp;

ALTER TABLE "project" DROP COLUMN migrate;
UPDATE  project 
SET     vcs_servers = project_tmp.vcs_servers
FROM    project_tmp
WHERE   project_tmp.id = project.id
DROP TABLE project_tmp;

ALTER TABLE "application" DROP COLUMN migrate;
UPDATE  "application" 
SET     vcs_strategy = application_tmp.vcs_strategy
FROM    application_tmp
WHERE   application_tmp.id = "application".id
DROP TABLE application_tmp;

ALTER TABLE "integration_model" DROP COLUMN migrate;
UPDATE  integration_model 
SET     public_configurations = integration_model_tmp.public_configurations
FROM    integration_model_tmp
WHERE   integration_model_tmp.id = integration_model.id
DROP TABLE integration_model_tmp;