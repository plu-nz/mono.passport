// Package ghauth signs in to GitHub with the OAuth device flow and talks to
// the small part of the REST API Passport needs, without the GitHub CLI.
//
// Passport is registered as the "Passport" OAuth App of the plu-nz organisation
// with device flow enabled. Device flow needs only the public client ID; there
// is no client secret.
package ghauth

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ClientID identifies the plu-nz "Passport" OAuth App. It is public.
const ClientID = "Ov23liE8ep7OS2M8Hfsy"

// Scope lets Passport create the private vault repository and push to it.
const Scope = "repo"

var (
	ErrExpired      = errors.New("The GitHub code expired. Start sign-in again")
	ErrDenied       = errors.New("GitHub sign-in was cancelled")
	ErrUnauthorized = errors.New("GitHub no longer accepts this sign-in. Sign in again")
	ErrRepoExists   = errors.New("A repository with this name already exists")
)

type Client struct {
	HTTP     *http.Client
	WebBase  string
	APIBase  string
	ClientID string
}

func New() *Client {
	return &Client{HTTP: &http.Client{Timeout: 30 * time.Second}, WebBase: "https://github.com", APIBase: "https://api.github.com", ClientID: ClientID}
}

// slowDownStep is how much longer to wait after "slow_down" when GitHub does
// not send a new interval.
var slowDownStep = 5 * time.Second

// Device is a pending device-flow sign-in. The device code stays in Go; only
// the user code and verification URL are shown to the user.
type Device struct {
	UserCode        string    `json:"userCode"`
	VerificationURI string    `json:"verificationUri"`
	Expires         time.Time `json:"expires"`
	deviceCode      string
	interval        time.Duration
}

func (c *Client) form(ctx context.Context, path string, values url.Values, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.WebBase+path, strings.NewReader(values.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	res, err := c.HTTP.Do(req)
	if err != nil {
		return errors.New("Unable to reach GitHub. Check your connection")
	}
	defer res.Body.Close()
	if res.StatusCode >= 500 {
		return fmt.Errorf("GitHub is unavailable (%d). Try again", res.StatusCode)
	}
	return json.NewDecoder(io.LimitReader(res.Body, 1<<20)).Decode(out)
}

// StartDevice asks GitHub for a user code.
func (c *Client) StartDevice(ctx context.Context) (*Device, error) {
	var r struct {
		DeviceCode      string `json:"device_code"`
		UserCode        string `json:"user_code"`
		VerificationURI string `json:"verification_uri"`
		ExpiresIn       int    `json:"expires_in"`
		Interval        int    `json:"interval"`
		Error           string `json:"error"`
	}
	if err := c.form(ctx, "/login/device/code", url.Values{"client_id": {c.ClientID}, "scope": {Scope}}, &r); err != nil {
		return nil, err
	}
	if r.Error != "" || r.DeviceCode == "" || r.UserCode == "" {
		return nil, fmt.Errorf("GitHub refused to start sign-in (%s)", r.Error)
	}
	if r.Interval <= 0 {
		r.Interval = 5
	}
	if r.ExpiresIn <= 0 {
		r.ExpiresIn = 900
	}
	return &Device{UserCode: r.UserCode, VerificationURI: r.VerificationURI, Expires: time.Now().Add(time.Duration(r.ExpiresIn) * time.Second), deviceCode: r.DeviceCode, interval: time.Duration(r.Interval) * time.Second}, nil
}

// Wait polls until the user approves, denies, the code expires or ctx ends,
// and returns the access token.
func (c *Client) Wait(ctx context.Context, d *Device) (string, error) {
	interval := d.interval
	for {
		select {
		case <-ctx.Done():
			return "", ctx.Err()
		case <-time.After(interval):
		}
		if time.Now().After(d.Expires) {
			return "", ErrExpired
		}
		var r struct {
			AccessToken string `json:"access_token"`
			Error       string `json:"error"`
			Interval    int    `json:"interval"`
		}
		err := c.form(ctx, "/login/oauth/access_token", url.Values{"client_id": {c.ClientID}, "device_code": {d.deviceCode}, "grant_type": {"urn:ietf:params:oauth:grant-type:device_code"}}, &r)
		if err != nil {
			if ctx.Err() != nil {
				return "", ctx.Err()
			}
			continue // a dropped request is retried at the next interval
		}
		switch r.Error {
		case "":
			if r.AccessToken == "" {
				return "", errors.New("GitHub returned no token")
			}
			return r.AccessToken, nil
		case "authorization_pending":
		case "slow_down":
			if r.Interval > 0 {
				interval = time.Duration(r.Interval) * time.Second
			} else {
				interval += slowDownStep
			}
		case "expired_token":
			return "", ErrExpired
		case "access_denied":
			return "", ErrDenied
		default:
			return "", fmt.Errorf("GitHub sign-in failed (%s)", r.Error)
		}
	}
}

func (c *Client) api(ctx context.Context, token, method, path string, body any, out any) (int, error) {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return 0, err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.APIBase+path, reader)
	if err != nil {
		return 0, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	res, err := c.HTTP.Do(req)
	if err != nil {
		return 0, errors.New("Unable to reach GitHub. Check your connection")
	}
	defer res.Body.Close()
	if res.StatusCode == http.StatusUnauthorized {
		return res.StatusCode, ErrUnauthorized
	}
	if out != nil && res.StatusCode < 300 {
		if err := json.NewDecoder(io.LimitReader(res.Body, 8<<20)).Decode(out); err != nil {
			return res.StatusCode, errors.New("GitHub sent an unexpected reply")
		}
	}
	return res.StatusCode, nil
}

type User struct {
	Login string `json:"login"`
	ID    int64  `json:"id"`
	Name  string `json:"name"`
}

// NoreplyEmail is the private commit address GitHub gives every account.
func (u User) NoreplyEmail() string {
	return strconv.FormatInt(u.ID, 10) + "+" + u.Login + "@users.noreply.github.com"
}

// DisplayName is the profile name, or the login when the profile has none.
func (u User) DisplayName() string {
	if name := strings.TrimSpace(u.Name); name != "" && !strings.ContainsAny(name, "<>()\r\n\x00") {
		return name
	}
	return u.Login
}

func (c *Client) User(ctx context.Context, token string) (User, error) {
	var u User
	status, err := c.api(ctx, token, http.MethodGet, "/user", nil, &u)
	if err != nil {
		return User{}, err
	}
	if status != http.StatusOK || u.Login == "" {
		return User{}, fmt.Errorf("GitHub did not return the account (%d)", status)
	}
	return u, nil
}

type Repo struct {
	Name          string   `json:"name"`
	FullName      string   `json:"fullName"`
	CloneURL      string   `json:"cloneUrl"`
	Private       bool     `json:"private"`
	DefaultBranch string   `json:"defaultBranch"`
	Topics        []string `json:"topics"`
}

type apiRepo struct {
	Name          string   `json:"name"`
	FullName      string   `json:"full_name"`
	CloneURL      string   `json:"clone_url"`
	Private       bool     `json:"private"`
	DefaultBranch string   `json:"default_branch"`
	Topics        []string `json:"topics"`
}

func (r apiRepo) repo() Repo {
	return Repo{Name: r.Name, FullName: r.FullName, CloneURL: r.CloneURL, Private: r.Private, DefaultBranch: r.DefaultBranch, Topics: r.Topics}
}

var repoNamePattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,100}$`)

// ValidRepoName follows GitHub's rules: letters, digits, ".", "-" and "_",
// at most 100 characters, and not "." or "..".
func ValidRepoName(name string) bool {
	return repoNamePattern.MatchString(name) && name != "." && name != ".." && !strings.HasSuffix(strings.ToLower(name), ".git")
}

// SetTopics replaces the topics of fullName ("owner/repo").
func (c *Client) SetTopics(ctx context.Context, token, fullName string, topics []string) error {
	status, err := c.api(ctx, token, http.MethodPut, "/repos/"+escapePath(fullName)+"/topics", map[string]any{"names": topics}, nil)
	if err != nil {
		return err
	}
	if status != http.StatusOK {
		return fmt.Errorf("GitHub did not tag the repository (%d)", status)
	}
	return nil
}

// OwnedRepos lists the repositories the account owns, up to 1000.
func (c *Client) OwnedRepos(ctx context.Context, token string) ([]Repo, error) {
	var repos []Repo
	for page := 1; page <= 10; page++ {
		var batch []apiRepo
		status, err := c.api(ctx, token, http.MethodGet, fmt.Sprintf("/user/repos?affiliation=owner&per_page=100&page=%d", page), nil, &batch)
		if err != nil {
			return nil, err
		}
		if status != http.StatusOK {
			return nil, fmt.Errorf("GitHub did not list repositories (%d)", status)
		}
		for _, r := range batch {
			repos = append(repos, r.repo())
		}
		if len(batch) < 100 {
			break
		}
	}
	return repos, nil
}

// HasBranch reports whether fullName ("owner/repo") has the given branch.
func (c *Client) HasBranch(ctx context.Context, token, fullName, branch string) (bool, error) {
	status, err := c.api(ctx, token, http.MethodGet, "/repos/"+escapePath(fullName)+"/branches/"+url.PathEscape(branch), nil, nil)
	if err != nil {
		return false, err
	}
	switch status {
	case http.StatusOK:
		return true, nil
	case http.StatusNotFound:
		return false, nil
	}
	return false, fmt.Errorf("GitHub did not answer about %s (%d)", fullName, status)
}

// CreatePrivateRepo creates an empty private repository in the account.
func (c *Client) CreatePrivateRepo(ctx context.Context, token, name, description string) (Repo, error) {
	var r apiRepo
	status, err := c.api(ctx, token, http.MethodPost, "/user/repos", map[string]any{"name": name, "private": true, "description": description, "auto_init": false, "has_issues": false, "has_wiki": false, "has_projects": false}, &r)
	if err != nil {
		return Repo{}, err
	}
	switch {
	case status == http.StatusCreated:
		if !r.Private || r.CloneURL == "" {
			return Repo{}, errors.New("GitHub did not create a private repository")
		}
		return r.repo(), nil
	case status == http.StatusUnprocessableEntity:
		return Repo{}, ErrRepoExists
	}
	return Repo{}, fmt.Errorf("GitHub did not create the repository (%d)", status)
}

func escapePath(fullName string) string {
	owner, repo, _ := strings.Cut(fullName, "/")
	return url.PathEscape(owner) + "/" + url.PathEscape(repo)
}
