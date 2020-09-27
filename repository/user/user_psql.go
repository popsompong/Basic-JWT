package userRepository

import (
	"database/sql"
	"jwt-course-refactored/models"
)

type UserRepository struct {
}

func logFatal(err error) {
	if err != nil {
		logFatal(err)
	}
}

func (u UserRepository) SignUp(db *sql.DB, user models.User) models.User {
	err := db.QueryRow("insert into users (email, password) values($1, $2) RETURNING id;",
		user.Email, user.Password).Scan(&user.ID)
	logFatal(err)

	user.Password = ""
	return user

}

func (u UserRepository) Login(db *sql.DB, user models.User) (models.User, error) {
	row := db.QueryRow("select * from users where email=$1", user.Email)
	err := row.Scan(&user.ID, &user.Email, &user.Password)

	if err != nil {
		return user, err
	}

	return user, nil
}
