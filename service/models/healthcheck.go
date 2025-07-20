package models

type HealthCheckResponse struct {
    Status string      `json:"status"`
    Msg    string      `json:"msg"`
    Sub    string      `json:"sub"`
    Name   string      `json:"name"`
    Data   interface{} `json:"data"`
    Data2  interface{} `json:"data2"`
}