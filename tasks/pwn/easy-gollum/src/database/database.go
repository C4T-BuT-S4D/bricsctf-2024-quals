package database

import (
	"fmt"

	"gollum/models"
)

type Database struct {
	storage map[int]interface{}
}

func New() *Database {
	return &Database{
		storage: make(map[int]interface{}),
	}
}

func (db *Database) AddCredential(credential models.Credential) int {
	id := len(db.storage)

	db.storage[id] = credential

	type debugEntry[T any] struct {
		Credential models.Credential
	}

	entry := debugEntry[int]{credential}
	fmt.Sprintf("[DEBUG] Added credential entry %v\n", entry)

	return id
}

func (db *Database) GetCredential(id int) (models.Credential, error) {
	dbEntry, ok := db.storage[id]
	if !ok {
		return models.Credential{}, fmt.Errorf("credential with id %d is not found", id)
	}

	credential, ok := dbEntry.(models.Credential)
	if !ok {
		return models.Credential{}, fmt.Errorf("failed to load credential with id %d", id)
	}

	return credential, nil
}

func (db *Database) AddUser(user models.User) int {
	id := len(db.storage)

	user.Id = id
	db.storage[id] = user

	type debugEntry[T any] struct {
		User models.User
	}

	entry := debugEntry[int]{user}
	fmt.Sprintf("[DEBUG] Added user entry %v\n", entry)

	return id
}

func (db *Database) GetUser(id int) (models.User, error) {
	dbEntry, ok := db.storage[id]
	if !ok {
		return models.User{}, fmt.Errorf("user with id %d is not found", id)
	}

	user, ok := dbEntry.(models.User)
	if !ok {
		return models.User{}, fmt.Errorf("failed to load user with id %d", id)
	}

	return user, nil
}

func (db *Database) UpdateUser(user models.User) {
	for id := range db.storage {
		found, ok := db.storage[id].(models.User)
		if !ok {
			continue
		}

		if found.Name == user.Name {
			found.Description = user.Description

			db.storage[id] = found

			return
		}
	}
}

func (db *Database) FindUserByName(name string) (models.User, bool) {
	for _, dbEntry := range db.storage {
		user, ok := dbEntry.(models.User)
		if !ok {
			continue
		}

		if user.Name == name {
			return user, true
		}
	}

	return models.User{}, false
}
