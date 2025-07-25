package middleware

import (
	"fmt"
	"net/http"

	h "github.com/RedHatInsights/sources-api-go/middleware/headers"
	"github.com/RedHatInsights/sources-api-go/util"
	"github.com/labstack/echo/v4"
)

func HandleErrors(next echo.HandlerFunc) echo.HandlerFunc {
	return func(c echo.Context) error {
		err := next(c)
		if err != nil {
			var (
				statusCode int
				message    interface{}
			)

			switch err.(type) {
			case util.ErrNotFound:
				statusCode = http.StatusNotFound
				message = util.NewErrorDoc(err.Error(), "404")
			case util.ErrBadRequest:
				statusCode = http.StatusBadRequest
				message = util.NewErrorDoc(err.Error(), "400")
			default:
				c.Logger().Error(err)

				uuid, ok := c.Get(h.InsightsRequestID).(string)
				if !ok {
					uuid = ""
				}

				statusCode = http.StatusInternalServerError
				message = util.ErrorDocWithRequestId(fmt.Sprintf("Internal Server Error: %v", err.Error()), "500", uuid)
			}

			return c.JSON(statusCode, message)
		}

		return nil
	}
}
