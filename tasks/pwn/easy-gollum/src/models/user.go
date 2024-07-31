package models

import "fmt"

type User struct {
	Id          int
	Name        string
	Description string

	CredentialId int
}

func (user User) String() string {
	if user.Description == "" {
		return user.Name
	} else {
		return fmt.Sprintf("%s \"%s\"", user.Name, user.Description)
	}
}
