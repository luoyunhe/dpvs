// Code generated by go-swagger; DO NOT EDIT.

package ipset

// This file was generated by the swagger tool.
// Editing this file might prove futile when you re-run the generate command

import (
	"net/http"

	"github.com/go-openapi/runtime/middleware"
)

// CreateHandlerFunc turns a function with the right signature into a create handler
type CreateHandlerFunc func(CreateParams) middleware.Responder

// Handle executing the request and returning a response
func (fn CreateHandlerFunc) Handle(params CreateParams) middleware.Responder {
	return fn(params)
}

// CreateHandler interface for that can handle valid create params
type CreateHandler interface {
	Handle(CreateParams) middleware.Responder
}

// NewCreate creates a new http.Handler for the create operation
func NewCreate(ctx *middleware.Context, handler CreateHandler) *Create {
	return &Create{Context: ctx, Handler: handler}
}

/*
	Create swagger:route PUT /ipset/{name} ipset create

Create an ipset named {name}.
*/
type Create struct {
	Context *middleware.Context
	Handler CreateHandler
}

func (o *Create) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	route, rCtx, _ := o.Context.RouteInfo(r)
	if rCtx != nil {
		*r = *rCtx
	}
	var Params = NewCreateParams()
	if err := o.Context.BindValidRequest(r, route, &Params); err != nil { // bind params
		o.Context.Respond(rw, r, route.Produces, route, err)
		return
	}

	res := o.Handler.Handle(Params) // actually handle the request
	o.Context.Respond(rw, r, route.Produces, route, res)

}
