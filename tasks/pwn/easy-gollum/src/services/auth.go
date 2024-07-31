package services

import (
	"fmt"

	"gollum/database"
	"gollum/models"
)

type AuthService struct {
	database *database.Database
}

func NewAuthService(database *database.Database) *AuthService {
	return &AuthService{
		database: database,
	}
}

func (auth *AuthService) Register(user models.User, credential models.Credential) (models.User, error) {
	_, ok := auth.database.FindUserByName(user.Name)
	if ok {
		return models.User{}, fmt.Errorf("user with name `%s` is already registered", user.Name)
	}

	credentialId := auth.database.AddCredential(credential)
	user.CredentialId = credentialId

	user.Id = auth.database.AddUser(user)

	return user, nil
}

func (auth *AuthService) Login(username, password string) (models.User, error) {
	user, ok := auth.database.FindUserByName(username)
	if !ok {
		return models.User{}, fmt.Errorf("user with name `%s` is not found", username)
	}

	credential, err := auth.database.GetCredential(user.CredentialId)
	if err != nil {
		return models.User{}, err
	}

	if !credential.IsSafe() {
		return models.User{}, fmt.Errorf("credential for user `%s` is too old, please change password", user.Name)
	}

	if !credential.Validate(password) {
		return models.User{}, fmt.Errorf("invalid password, password should be `%s`", credential)
	}

	return user, nil
}
