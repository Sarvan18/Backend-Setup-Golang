package handleError

type ErrorWithCode struct {
	Error      string
	StatusCode uint
}

func HandleErrorWithCode(e ErrorWithCode) ErrorWithCode {
	return ErrorWithCode{
		Error:      e.Error,
		StatusCode: e.StatusCode,
	}
}
