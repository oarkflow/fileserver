package requests

import (
	"github.com/gofiber/fiber/v2"
	"github.com/gookit/validate"
)

func Validate[T any](ctx *fiber.Ctx) (T, error) {
	var request T
	err := ctx.BodyParser(&request)
	if err != nil {
		return request, err
	}
	v := validate.Struct(request)
	if !v.Validate() {
		return request, v.Errors
	}
	return request, nil
}
