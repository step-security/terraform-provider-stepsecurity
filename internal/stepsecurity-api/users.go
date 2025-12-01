package stepsecurityapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
)

type User struct {
	ID          string       `json:"id,omitempty"`
	Email       string       `json:"email,omitempty"`
	UserName    string       `json:"user_name,omitempty"`
	EmailSuffix string       `json:"email_suffix,omitempty"`
	SSOGroup    string       `json:"sso_groups,omitempty"`
	Identifier  string       `json:"identifier,omitempty"`
	AuthType    string       `json:"auth_type,omitempty"`
	AddedAt     int64        `json:"added_at,omitempty"`
	UpdatedAt   int64        `json:"updated_at,omitempty"`
	UpdatedBy   string       `json:"updated_by,omitempty"`
	Policies    []UserPolicy `json:"policies,omitempty"`
}

type UserPolicy struct {
	Type         string   `json:"type,omitempty"`
	Role         string   `json:"role,omitempty"`
	Scope        string   `json:"scope,omitempty"`
	Organization string   `json:"organization,omitempty"`
	Repos        []string `json:"repos,omitempty"`
	Server       string   `json:"server,omitempty"`
	Projects     []string `json:"projects,omitempty"`
}

type CreateUserRequest struct {
	Email       string       `json:"email"`
	UserName    string       `json:"user_name"`
	EmailSuffix string       `json:"email_suffix"`
	SSOGroup    string       `json:"sso_group"`
	AuthType    string       `json:"auth_type"`
	Policies    []UserPolicy `json:"policies"`
}

type CreateUserResponse struct {
	ID         string `json:"id"`
	Identifier string `json:"identifier"`
}

type createUserRequestInternal struct {
	Emails        []string     `json:"emails"`
	UserNames     []string     `json:"user_names"`
	EmailSuffixes []string     `json:"email_suffixes"`
	SSOGroups     []string     `json:"sso_groups"`
	Identifier    string       `json:"identifier"`
	AuthType      string       `json:"auth_type"`
	Policies      []UserPolicy `json:"policies"`
}

type createUserResponseInternal struct {
	UsersAdded  []CreateUserResponse `json:"users_added"`
	FailedUsers []string             `json:"failed_users"`
}

type UpdateUserRequest struct {
	UserID   string       `json:"user_id"`
	Policies []UserPolicy `json:"policies"`
}

func (c *APIClient) ListUsers(ctx context.Context) ([]User, error) {
	URI := fmt.Sprintf("%s/v1/%s/users", c.BaseURL, c.Customer)
	req, err := http.NewRequest("GET", URI, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create request: %w", err)
	}

	body, err := c.do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to get users: %w", err)
	}

	var users []User
	if err := json.Unmarshal(body, &users); err != nil {
		return nil, fmt.Errorf("failed to unmarshal users: %w", err)
	}

	return users, nil
}

func (c *APIClient) CreateUser(ctx context.Context, user CreateUserRequest) (*CreateUserResponse, error) {

	resp := &CreateUserResponse{}

	convertedUser := createUserRequestInternal{
		AuthType: user.AuthType,
		Policies: user.Policies,
	}
	if user.Email != "" {
		convertedUser.Emails = []string{user.Email}
	}
	if user.UserName != "" {
		convertedUser.UserNames = []string{user.UserName}
	}
	if user.EmailSuffix != "" {
		convertedUser.EmailSuffixes = []string{user.EmailSuffix}
	}
	if user.SSOGroup != "" {
		convertedUser.SSOGroups = []string{user.SSOGroup}
	}

	URI := fmt.Sprintf("%s/v1/%s/users", c.BaseURL, c.Customer)
	respBody, err := c.post(ctx, URI, convertedUser)
	if err != nil {
		return resp, fmt.Errorf("failed to create user: %w", err)
	}

	var createUserResponse createUserResponseInternal
	if err := json.Unmarshal(respBody, &createUserResponse); err != nil {
		return resp, fmt.Errorf("failed to unmarshal create user response: %w", err)
	}

	if len(createUserResponse.UsersAdded) == 0 {
		return resp, fmt.Errorf("failed to create user: %w", err)
	}

	resp = &createUserResponse.UsersAdded[0]
	return resp, nil
}

func (c *APIClient) GetUser(ctx context.Context, userID string) (*User, error) {
	URI := fmt.Sprintf("%s/v1/%s/users/%s", c.BaseURL, c.Customer, userID)
	respBody, err := c.get(ctx, URI)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	var user User
	if err := json.Unmarshal(respBody, &user); err != nil {
		return nil, fmt.Errorf("failed to unmarshal user: %w", err)
	}

	return &user, nil
}

func (c *APIClient) UpdateUser(ctx context.Context, updateUserRequest UpdateUserRequest) error {

	URI := fmt.Sprintf("%s/v1/%s/users/%s", c.BaseURL, c.Customer, updateUserRequest.UserID)
	if _, err := c.put(ctx, URI, updateUserRequest); err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}
	return nil
}

func (c *APIClient) DeleteUser(ctx context.Context, userID string) error {
	URI := fmt.Sprintf("%s/v1/%s/users/%s", c.BaseURL, c.Customer, userID)
	if _, err := c.delete(ctx, URI); err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}
	return nil
}
