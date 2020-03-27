package repositoriesmanager

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/go-gorp/gorp"

	"github.com/ovh/cds/engine/api/observability"
	"github.com/ovh/cds/engine/api/services"
	"github.com/ovh/cds/sdk"
	"github.com/ovh/cds/sdk/log"
)

func LoadByName(ctx context.Context, db gorp.SqlExecutor, vcsName string) (sdk.VCSConfiguration, error) {
	var vcsServer sdk.VCSConfiguration
	srvs, err := services.LoadAllByType(ctx, db, services.TypeVCS)
	if err != nil {
		return vcsServer, sdk.WrapError(err, "Unable to load services")
	}
	if _, _, err := services.NewClient(db, srvs).DoJSONRequest(ctx, "GET", fmt.Sprintf("/vcs/%s", vcsName), nil, &vcsServer); err != nil {
		return vcsServer, sdk.WithStack(err)
	}
	return vcsServer, nil
}

//LoadAll Load all RepositoriesManager from the database
func LoadAll(ctx context.Context, db *gorp.DbMap) (map[string]sdk.VCSConfiguration, error) {
	srvs, err := services.LoadAllByType(ctx, db, services.TypeVCS)
	if err != nil {
		return nil, sdk.WrapError(err, "Unable to load services")
	}

	vcsServers := make(map[string]sdk.VCSConfiguration)
	if _, _, err := services.NewClient(db, srvs).DoJSONRequest(ctx, "GET", "/vcs", nil, &vcsServers); err != nil {
		return nil, sdk.WithStack(err)
	}
	return vcsServers, nil
}

type updateVCSServerFunc func(db gorp.SqlExecutor, vcsServers *sdk.ProjectVCSServer) error

type vcsConsumer struct {
	proj                *sdk.Project
	vcsServer           *sdk.ProjectVCSServer
	dbFunc              func(ctx context.Context) *gorp.DbMap
	updateVCSServerFunc updateVCSServerFunc
}

func (c *vcsConsumer) Name() string {
	return c.vcsServer.Name
}

type vcsClient struct {
	token               string
	secret              string
	projectKey          string
	vcsServer           *sdk.ProjectVCSServer // This reference is used when we have to update the cds_server data (ie for bitbucket cloud)
	created             int64                 // Timestamp .Unix() of creation
	srvs                []sdk.Service         // This reference is used as a cache
	db                  gorp.SqlExecutor      // This reference is used to get VCS services in the database, and update cds_server data (ie for bitbucket cloud)
	updateVCSServerFunc updateVCSServerFunc   // We need this reference to update the vcs_server data each time bitbucket cloud is giving us a new token
}

func (c *vcsClient) Name() string {
	return c.vcsServer.Name
}

// NewVCSServerConsumer returns a sdk.VCSServer wrapping vcs µServices calls
func NewVCSServerConsumer(dbFunc func(ctx context.Context) *gorp.DbMap, proj *sdk.Project, vcsServer *sdk.ProjectVCSServer, updateVCSServerFunc updateVCSServerFunc) (sdk.VCSServer, error) {
	if vcsServer.IsBlurred() {
		panic("unable to instanciate new VCS Consumer from blurred vcs project server")
	}
	return &vcsConsumer{
		dbFunc:              dbFunc,
		proj:                proj,
		vcsServer:           vcsServer,
		updateVCSServerFunc: updateVCSServerFunc,
	}, nil
}

func (c *vcsConsumer) AuthorizeRedirect(ctx context.Context) (string, string, error) {
	db := c.dbFunc(ctx)
	srv, err := services.LoadAllByType(ctx, db, services.TypeVCS)
	if err != nil {
		return "", "", sdk.WithStack(err)
	}

	res := map[string]string{}
	path := fmt.Sprintf("/vcs/%s/authorize", c.Name())
	log.Info(ctx, "Performing request on %s", path)
	if _, _, err := services.NewClient(db, srv).DoJSONRequest(ctx, "GET", path, nil, &res); err != nil {
		return "", "", sdk.WithStack(err)
	}

	return res["token"], res["url"], nil
}

func (c *vcsConsumer) AuthorizeToken(ctx context.Context, token string, secret string) (string, string, error) {
	db := c.dbFunc(ctx)
	srv, err := services.LoadAllByType(ctx, db, services.TypeVCS)
	if err != nil {
		return "", "", sdk.WithStack(err)
	}

	body := map[string]string{
		"token":  token,
		"secret": secret,
	}

	res := map[string]string{}
	path := fmt.Sprintf("/vcs/%s/authorize", c.Name())
	if _, _, err := services.NewClient(db, srv).DoJSONRequest(ctx, "POST", path, body, &res); err != nil {
		return "", "", sdk.WithStack(err)
	}

	return res["token"], res["secret"], nil
}

func (c *vcsConsumer) GetAuthorizedClient(ctx context.Context, token, secret string, created int64) (sdk.VCSAuthorizedClient, error) {
	s := c.vcsServer

	srvs, err := services.LoadAllByType(ctx, c.dbFunc(ctx), services.TypeVCS)
	if err != nil {
		return nil, sdk.WithStack(err)
	}

	return &vcsClient{
		vcsServer:           s,
		updateVCSServerFunc: c.updateVCSServerFunc,
		srvs:                srvs,
		db:                  c.dbFunc(ctx),
		token:               token,
		projectKey:          c.proj.Key,
		created:             created,
		secret:              secret,
	}, nil
}

//AuthorizedClient returns an implementation of AuthorizedClient wrapping calls to vcs uService
func AuthorizedClient(ctx context.Context, db gorp.SqlExecutor, projectKey string, vcsServer *sdk.ProjectVCSServer, updateVCSServerFunc updateVCSServerFunc) (sdk.VCSAuthorizedClient, error) {
	if vcsServer == nil {
		return nil, sdk.ErrNoReposManagerClientAuth
	}

	srvs, err := services.LoadAllByType(ctx, db, services.TypeVCS)
	if err != nil {
		return nil, sdk.WithStack(err)
	}
	var created int64

	if _, ok := vcsServer.Data["created"]; ok {
		created, err = strconv.ParseInt(vcsServer.Data["created"], 10, 64)
		if err != nil {
			return nil, sdk.WithStack(err)
		}
	}

	vcs := &vcsClient{
		token:      vcsServer.Data["token"],
		secret:     vcsServer.Data["secret"],
		created:    created,
		srvs:       srvs,
		db:         db,
		projectKey: projectKey,
	}
	return vcs, nil
}

func (c *vcsClient) doJSONRequest(ctx context.Context, method, path string, in interface{}, out interface{}) (int, error) {
	headers, code, err := services.NewClient(c.db, c.srvs).DoJSONRequest(ctx, method, path, in, out, func(req *http.Request) {
		req.Header.Set(sdk.HeaderXAccessToken, base64.StdEncoding.EncodeToString([]byte(c.token)))
		req.Header.Set(sdk.HeaderXAccessTokenSecret, base64.StdEncoding.EncodeToString([]byte(c.secret)))
		if c.created != 0 {
			req.Header.Set(sdk.HeaderXAccessTokenCreated, base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%d", c.created))))
		}
	})

	if code >= 400 {
		switch code {
		case http.StatusUnauthorized:
			err = sdk.WrapError(sdk.ErrNoReposManagerClientAuth, "%s", err)
		case http.StatusBadRequest:
			err = sdk.WrapError(sdk.ErrWrongRequest, "%s", err)
		case http.StatusNotFound:
			err = sdk.WrapError(sdk.ErrNotFound, "%s", err)
		case http.StatusForbidden:
			err = sdk.WrapError(sdk.ErrForbidden, "%s", err)
		default:
			err = sdk.WrapError(sdk.ErrUnknownError, "%s", err)
		}
	}

	if err != nil {
		return code, sdk.WithStack(err)
	}
	err = c.checkAccessToken(ctx, headers)

	return code, sdk.WithStack(err)
}

func (c *vcsClient) postMultipart(ctx context.Context, path string, fileContent []byte, out interface{}) (int, error) {
	return services.PostMultipart(ctx, c.db, c.srvs, "POST", path, fileContent, out, func(req *http.Request) {
		req.Header.Set(sdk.HeaderXAccessToken, base64.StdEncoding.EncodeToString([]byte(c.token)))
		req.Header.Set(sdk.HeaderXAccessTokenSecret, base64.StdEncoding.EncodeToString([]byte(c.secret)))
	})
}

func (c *vcsClient) checkAccessToken(ctx context.Context, header http.Header) error {
	if newAccessToken := header.Get(sdk.HeaderXAccessToken); newAccessToken != "" {
		c.token = newAccessToken
		c.vcsServer.Data["token"] = c.token
		c.vcsServer.Data["created"] = fmt.Sprintf("%d", time.Now().Unix())

		if err := c.updateVCSServerFunc(c.db, c.vcsServer); err != nil {
			return sdk.WrapError(err, "cannot update vcsservers for project %s", c.projectKey)
		}
	}
	return nil
}

func (c *vcsClient) Repos(ctx context.Context) ([]sdk.VCSRepo, error) {
	repos := []sdk.VCSRepo{}
	path := fmt.Sprintf("/vcs/%s/repos", c.Name())
	if _, err := c.doJSONRequest(ctx, "GET", path, nil, &repos); err != nil {
		return nil, sdk.WrapError(err, "unable to get repositories from %s", c.Name())
	}
	return repos, nil
}

func (c *vcsClient) RepoByFullname(ctx context.Context, fullname string) (sdk.VCSRepo, error) {
	var end func()
	ctx, end = observability.Span(ctx, "repositories.RepoByFullname")
	defer end()

	repo := sdk.VCSRepo{}
	path := fmt.Sprintf("/vcs/%s/repos/%s", c.Name(), fullname)
	if _, err := c.doJSONRequest(ctx, "GET", path, nil, &repo); err != nil {
		return repo, sdk.WrapError(err, "unable to get repo %s from %s", fullname, c.Name())
	}

	return repo, nil
}

func (c *vcsClient) Tags(ctx context.Context, fullname string) ([]sdk.VCSTag, error) {
	tags := []sdk.VCSTag{}
	path := fmt.Sprintf("/vcs/%s/repos/%s/tags", c.Name(), fullname)
	if _, err := c.doJSONRequest(ctx, "GET", path, nil, &tags); err != nil {
		return nil, sdk.WrapError(err, "unable to get tags on repository %s from %s", fullname, c.Name())
	}
	return tags, nil
}

func (c *vcsClient) Branches(ctx context.Context, fullname string) ([]sdk.VCSBranch, error) {
	branches := []sdk.VCSBranch{}
	path := fmt.Sprintf("/vcs/%s/repos/%s/branches", c.Name(), fullname)
	if _, err := c.doJSONRequest(ctx, "GET", path, nil, &branches); err != nil {
		return nil, sdk.WrapError(err, "unable to find branches on repository %s from %s", fullname, c.Name())
	}
	return branches, nil
}

func (c *vcsClient) Branch(ctx context.Context, fullname string, branchName string) (*sdk.VCSBranch, error) {
	branch := sdk.VCSBranch{}
	path := fmt.Sprintf("/vcs/%s/repos/%s/branches/?branch=%s", c.Name(), fullname, url.QueryEscape(branchName))
	if _, err := c.doJSONRequest(ctx, "GET", path, nil, &branch); err != nil {
		return nil, sdk.WrapError(err, "unable to find branch %s on repository %s from %s", branchName, fullname, c.Name())
	}
	return &branch, nil
}

// DefaultBranch get default branch from given repository
func DefaultBranch(ctx context.Context, c sdk.VCSAuthorizedClient, fullname string) (sdk.VCSBranch, error) {
	branches, err := c.Branches(ctx, fullname)
	if err != nil {
		return sdk.VCSBranch{}, sdk.WrapError(err, "Unable to list branches on repository %s", fullname)
	}
	for _, b := range branches {
		if b.Default {
			return b, nil
		}
	}
	return sdk.VCSBranch{}, sdk.NewErrorFrom(sdk.ErrNotFound, "unable to find default branch on repository %s (among %d branches)", fullname, len(branches))
}

func (c *vcsClient) Commits(ctx context.Context, fullname, branch, since, until string) ([]sdk.VCSCommit, error) {
	commits := []sdk.VCSCommit{}
	path := fmt.Sprintf("/vcs/%s/repos/%s/branches/commits?branch=%s&since=%s&until=%s", c.Name(), fullname, url.QueryEscape(branch), url.QueryEscape(since), url.QueryEscape(until))
	if code, err := c.doJSONRequest(ctx, "GET", path, nil, &commits); err != nil {
		if code != http.StatusNotFound {
			return nil, sdk.WrapError(err, "unable to find commits on repository %s from %s", fullname, c.Name())
		}
	}
	return commits, nil
}

func (c *vcsClient) CommitsBetweenRefs(ctx context.Context, fullname, base, head string) ([]sdk.VCSCommit, error) {
	var commits []sdk.VCSCommit
	path := fmt.Sprintf("/vcs/%s/repos/%s/commits?base=%s&head=%s", c.Name(), fullname, url.QueryEscape(base), url.QueryEscape(head))
	if code, err := c.doJSONRequest(ctx, "GET", path, nil, &commits); err != nil {
		if code != http.StatusNotFound {
			return nil, sdk.WrapError(err, "unable to find commits on repository %s from %s", fullname, c.Name())
		}
	}
	return commits, nil
}

func (c *vcsClient) Commit(ctx context.Context, fullname, hash string) (sdk.VCSCommit, error) {
	commit := sdk.VCSCommit{}
	path := fmt.Sprintf("/vcs/%s/repos/%s/commits/%s", c.Name(), fullname, hash)
	if code, err := c.doJSONRequest(ctx, "GET", path, nil, &commit); err != nil {
		if code != http.StatusNotFound {
			return commit, sdk.WrapError(err, "unable to find commit %s on repository %s from %s", hash, fullname, c.Name())
		}
	}
	return commit, nil
}

func (c *vcsClient) PullRequest(ctx context.Context, fullname string, ID int) (sdk.VCSPullRequest, error) {
	pr := sdk.VCSPullRequest{}
	path := fmt.Sprintf("/vcs/%s/repos/%s/pullrequests/%d", c.Name(), fullname, ID)
	if code, err := c.doJSONRequest(ctx, "GET", path, nil, &pr); err != nil {
		if code != http.StatusNotFound {
			return pr, sdk.WrapError(err, "unable to find pullrequest %d on repository %s from %s", ID, fullname, c.Name())
		}
		return pr, sdk.WithStack(sdk.ErrNotFound)
	}
	return pr, nil
}

func (c *vcsClient) PullRequests(ctx context.Context, fullname string) ([]sdk.VCSPullRequest, error) {
	prs := []sdk.VCSPullRequest{}
	path := fmt.Sprintf("/vcs/%s/repos/%s/pullrequests", c.Name(), fullname)
	if _, err := c.doJSONRequest(ctx, "GET", path, nil, &prs); err != nil {
		return nil, sdk.WrapError(err, "unable to find pullrequests on repository %s from %s", fullname, c.Name())
	}
	return prs, nil
}

func (c *vcsClient) PullRequestComment(ctx context.Context, fullname string, body sdk.VCSPullRequestCommentRequest) error {
	path := fmt.Sprintf("/vcs/%s/repos/%s/pullrequests/comments", c.Name(), fullname)
	if _, err := c.doJSONRequest(ctx, "POST", path, body, nil); err != nil {
		return sdk.WrapError(err, "unable to post pullrequest comments on repository %s from %s", fullname, c.Name())
	}
	return nil
}

func (c *vcsClient) PullRequestCreate(ctx context.Context, fullname string, pr sdk.VCSPullRequest) (sdk.VCSPullRequest, error) {
	path := fmt.Sprintf("/vcs/%s/repos/%s/pullrequests", c.Name(), fullname)
	if _, err := c.doJSONRequest(ctx, "POST", path, pr, &pr); err != nil {
		return pr, sdk.WrapError(err, "unable to create pullrequest on repository %s from %s", fullname, c.Name())
	}
	return pr, nil
}

func (c *vcsClient) CreateHook(ctx context.Context, fullname string, hook *sdk.VCSHook) error {
	path := fmt.Sprintf("/vcs/%s/repos/%s/hooks", c.Name(), fullname)
	_, err := c.doJSONRequest(ctx, "POST", path, hook, hook)
	if err != nil {
		log.Error(ctx, "CreateHook> %v", err)
		return sdk.NewErrorFrom(sdk.ErrUnknownError, "unable to create hook on repository %s from %s", fullname, c.Name())
	}
	return nil
}

func (c *vcsClient) UpdateHook(ctx context.Context, fullname string, hook *sdk.VCSHook) error {
	path := fmt.Sprintf("/vcs/%s/repos/%s/hooks", c.Name(), fullname)
	_, err := c.doJSONRequest(ctx, "PUT", path, hook, hook)
	if err != nil {
		log.Error(ctx, "UpdateHook> %v", err)
		return sdk.NewErrorFrom(sdk.ErrUnknownError, "unable to update hook %s on repository %s from %s", hook.ID, fullname, c.Name())
	}
	return nil
}

func (c *vcsClient) GetHook(ctx context.Context, fullname, u string) (sdk.VCSHook, error) {
	path := fmt.Sprintf("/vcs/%s/repos/%s/hooks?url=%s", c.Name(), fullname, url.QueryEscape(u))
	hook := &sdk.VCSHook{}
	_, err := c.doJSONRequest(ctx, "GET", path, nil, hook)
	return *hook, sdk.WrapError(err, "unable to get hook %s on repository %s from %s", u, fullname, c.Name())
}

func (c *vcsClient) DeleteHook(ctx context.Context, fullname string, hook sdk.VCSHook) error {
	// If we are not able to remove anything, just ignore
	if hook.URL == "" && hook.ID == "" {
		return nil
	}
	path := fmt.Sprintf("/vcs/%s/repos/%s/hooks?url=%s&id=%s", c.Name(), fullname, url.QueryEscape(hook.URL), hook.ID)
	_, err := c.doJSONRequest(ctx, "DELETE", path, nil, nil)
	return sdk.WrapError(err, "unable to delete hook on repository %s from %s", fullname, c.Name())
}

func (c *vcsClient) GetEvents(ctx context.Context, fullname string, dateRef time.Time) ([]interface{}, time.Duration, error) {
	res := struct {
		Events []interface{} `json:"events"`
		Delay  time.Duration `json:"delay"`
	}{}

	path := fmt.Sprintf("/vcs/%s/repos/%s/events?since=%d", c.Name(), fullname, dateRef.Unix())
	if _, err := c.doJSONRequest(ctx, "GET", path, nil, &res); err != nil {
		return nil, time.Duration(0), sdk.WrapError(err, "unable to get events on repository %s from %s", fullname, c.Name())
	}

	return res.Events, res.Delay, nil
}

func (c *vcsClient) PushEvents(ctx context.Context, fullname string, evts []interface{}) ([]sdk.VCSPushEvent, error) {
	events := []sdk.VCSPushEvent{}
	path := fmt.Sprintf("/vcs/%s/repos/%s/events?filter=push", c.Name(), fullname)
	if _, err := c.doJSONRequest(ctx, "POST", path, evts, &events); err != nil {
		return nil, sdk.WrapError(err, "unable to filter push events on repository %s from %s", fullname, c.Name())
	}
	return events, nil
}

func (c *vcsClient) CreateEvents(ctx context.Context, fullname string, evts []interface{}) ([]sdk.VCSCreateEvent, error) {
	events := []sdk.VCSCreateEvent{}
	path := fmt.Sprintf("/vcs/%s/repos/%s/events?filter=create", c.Name(), fullname)
	if _, err := c.doJSONRequest(ctx, "POST", path, evts, &events); err != nil {
		return nil, sdk.WrapError(err, "unable to filter create events on repository %s from %s", fullname, c.Name())
	}
	return events, nil
}

func (c *vcsClient) DeleteEvents(ctx context.Context, fullname string, evts []interface{}) ([]sdk.VCSDeleteEvent, error) {
	events := []sdk.VCSDeleteEvent{}
	path := fmt.Sprintf("/vcs/%s/repos/%s/events?filter=delete", c.Name(), fullname)
	if _, err := c.doJSONRequest(ctx, "POST", path, evts, &events); err != nil {
		return nil, sdk.WrapError(err, "unable to filter delete events on repository %s from %s", fullname, c.Name())
	}
	return events, nil
}

func (c *vcsClient) PullRequestEvents(ctx context.Context, fullname string, evts []interface{}) ([]sdk.VCSPullRequestEvent, error) {
	events := []sdk.VCSPullRequestEvent{}
	path := fmt.Sprintf("/vcs/%s/repos/%s/events?filter=pullrequests", c.Name(), fullname)
	if _, err := c.doJSONRequest(ctx, "POST", path, evts, &events); err != nil {
		return nil, sdk.WrapError(err, "unable to filter pull request events on repository %s from %s", fullname, c.Name())
	}
	return events, nil
}

func (c *vcsClient) SetStatus(ctx context.Context, event sdk.Event) error {
	path := fmt.Sprintf("/vcs/%s/status", c.Name())
	_, err := c.doJSONRequest(ctx, "POST", path, event, nil)
	return sdk.WrapError(err, "unable to set status on %s (workflow: %s, application: %s)", event.WorkflowName, event.ApplicationName, c.Name())
}

func (c *vcsClient) Release(ctx context.Context, fullname, tagName, releaseTitle, releaseDescription string) (*sdk.VCSRelease, error) {
	res := struct {
		Tag         string `json:"tag"`
		Title       string `json:"title"`
		Description string `json:"description"`
	}{
		Tag:         tagName,
		Title:       releaseTitle,
		Description: releaseDescription,
	}

	release := sdk.VCSRelease{}
	path := fmt.Sprintf("/vcs/%s/repos/%s/releases", c.Name(), fullname)
	_, err := c.doJSONRequest(ctx, "POST", path, &res, &release)
	if err != nil {
		return nil, sdk.WithStack(err)
	}
	return &release, nil
}

func (c *vcsClient) UploadReleaseFile(ctx context.Context, fullname string, releaseName, uploadURL string, artifactName string, r io.ReadCloser) error {
	path := fmt.Sprintf("/vcs/%s/repos/%s/releases/%s/artifacts/%s", c.Name(), fullname, releaseName, artifactName)
	defer r.Close()

	fileContent, err := ioutil.ReadAll(r)
	if err != nil {
		return sdk.WithStack(err)
	}

	if _, err := c.postMultipart(ctx, path, fileContent, nil); err != nil {
		return sdk.WithStack(err)
	}
	return nil
}

func (c *vcsClient) ListForks(ctx context.Context, repo string) ([]sdk.VCSRepo, error) {
	forks := []sdk.VCSRepo{}
	path := fmt.Sprintf("/vcs/%s/repos/%s/forks", c.Name(), repo)
	if _, err := c.doJSONRequest(ctx, "GET", path, nil, &forks); err != nil {
		return nil, sdk.WithStack(err)
	}
	return forks, nil
}

func (c *vcsClient) ListStatuses(ctx context.Context, repo string, ref string) ([]sdk.VCSCommitStatus, error) {
	statuses := []sdk.VCSCommitStatus{}
	path := fmt.Sprintf("/vcs/%s/repos/%s/commits/%s/statuses", c.Name(), repo, ref)
	if _, err := c.doJSONRequest(ctx, "GET", path, nil, &statuses); err != nil {
		return nil, sdk.WithStack(err)
	}
	return statuses, nil
}

func (c *vcsClient) GrantWritePermission(ctx context.Context, repo string) error {
	path := fmt.Sprintf("/vcs/%s/repos/%s/grant", c.Name(), repo)
	if _, err := c.doJSONRequest(ctx, "POST", path, nil, nil); err != nil {
		return sdk.WithStack(err)
	}
	return nil
}

func (c *vcsClient) GetAccessToken(_ context.Context) string {
	return ""
}

// WebhooksInfos is a set of info about webhooks
type WebhooksInfos struct {
	WebhooksSupported  bool     `json:"webhooks_supported"`
	WebhooksDisabled   bool     `json:"webhooks_disabled"`
	GerritHookDisabled bool     `json:"gerrithook_disabled"`
	Icon               string   `json:"webhooks_icon"`
	Events             []string `json:"events"`
}

// GetWebhooksInfos returns webhooks_supported, webhooks_disabled, webhooks_creation_supported, webhooks_creation_disabled for a vcs server
func GetWebhooksInfos(ctx context.Context, c sdk.VCSAuthorizedClient) (WebhooksInfos, error) {
	client, ok := c.(*vcsClient)
	if !ok {
		return WebhooksInfos{}, fmt.Errorf("Polling infos cast error")
	}
	res := WebhooksInfos{}
	path := fmt.Sprintf("/vcs/%s/webhooks", client.Name())
	if _, err := client.doJSONRequest(ctx, "GET", path, nil, &res); err != nil {
		return WebhooksInfos{}, sdk.WithStack(err)
	}
	return res, nil
}

// PollingInfos is a set of info about polling functions
type PollingInfos struct {
	PollingSupported bool `json:"polling_supported"`
	PollingDisabled  bool `json:"polling_disabled"`
}

// GetPollingInfos returns polling_supported and polling_disabled for a vcs server
func GetPollingInfos(ctx context.Context, c sdk.VCSAuthorizedClient, prj sdk.Project) (PollingInfos, error) {
	client, ok := c.(*vcsClient)
	if !ok {
		return PollingInfos{}, fmt.Errorf("Polling infos cast error")
	}
	res := PollingInfos{}
	path := fmt.Sprintf("/vcs/%s/polling", client.Name())
	if _, err := client.doJSONRequest(ctx, "GET", path, nil, &res); err != nil {
		return PollingInfos{}, sdk.WrapError(err, "project %s", prj.Key)
	}
	return res, nil
}
