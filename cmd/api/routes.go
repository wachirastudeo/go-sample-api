package main

import (
	_ "backend/cmd/api/docs" // เปลี่ยนชื่อโมดูลให้ตรงกับชื่อใน go.mod
	"net/http"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	httpSwagger "github.com/swaggo/http-swagger"
)

func (app *application) routes() http.Handler {

	// Create a router mux
	mux := chi.NewRouter()

	// Add middleware
	mux.Use(middleware.Recoverer)
	mux.Use(app.enableCORS)

	// Register Swagger
	mux.Get("/swagger/*", httpSwagger.WrapHandler)

	// Register the API routes under "/api/v1"
	mux.Route("/api/v1", func(r chi.Router) {
		// Public routes
		r.Get("/", app.Home)
		r.Get("/about", app.About)
		r.Get("/demomovies", app.AllDemoMovies)

		// Authenticated routes
		r.Post("/authenticate", app.authenticate)
		r.Get("/refresh", app.refreshToken)
		r.Get("/logout", app.logout)

		// Protected routes
		r.With(app.jwtMiddleware).Get("/admin/movies", app.MovieCatalog)
		r.With(app.jwtMiddleware).Get("/admin/movies/{id}", app.MovieForEdit)
		r.With(app.jwtMiddleware).Post("/admin/movies", app.InsertMovie)
		r.With(app.jwtMiddleware).Put("/admin/movies/{id}", app.UpdateMovie)
		r.With(app.jwtMiddleware).Delete("/admin/movies/{id}", app.DeleteMovie)

		r.Get("/movies", app.AllMovies)
		r.Get("/movies/{id}", app.GetMovie)
		r.Get("/genres", app.AllGenres)

		// Admin routes
		r.Route("/admin", func(r chi.Router) {

			// Protected routes
			r.Use(app.authRequired)

			r.Get("/movies", app.MovieCatalog)
			r.Get("/movies/{id}", app.MovieForEdit)
			r.Post("/movies", app.InsertMovie)
			r.Put("/movies/{id}", app.UpdateMovie)
			r.Delete("/movies/{id}", app.DeleteMovie)
		})
	})

	return mux
}
