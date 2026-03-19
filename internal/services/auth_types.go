package services

type RegisterInput struct {
	Email     string
	Username  string
	FirstName string
	LastName  string
	Password  string
}

type LoginInput struct {
	Email    string
	Password string
}

type RefreshInput struct {
	RefreshToken string
}

type LogoutInput struct {
	RefreshToken string
}

type LoginResult struct {
	AccessToken  string
	RefreshToken string
}

type RefreshResult struct {
	AccessToken string
}

type UserResult struct {
	ID        string
	FirstName string
	LastName  string
	Email     string
	Username  string
}
