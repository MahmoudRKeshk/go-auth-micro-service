package common

type ErrorResponse struct {
	Code    string      `json:"code"`
	Message string      `json:"message"`
	Details interface{} `json:"details"`
}