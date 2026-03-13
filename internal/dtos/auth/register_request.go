package auth

type RegisterRequest struct {
	Email    string `json:"email"`
	Password string `json:"password"`
	Username string `json:"username"`
	FirstName string `json:"first_name"`
	LastName string `json:"last_name"`
}