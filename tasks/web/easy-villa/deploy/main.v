module main

import os
import vweb

struct App {
	vweb.Context
}

@['/'; get; post]
fn (mut app App) index() vweb.Result {
	return $vweb.html()
}

@['/villa'; get; post]
fn (mut app App) villa() vweb.Result {
	if app.req.method == .post {
		os.write_file('villa.html', $tmpl('template.html')) or { panic(err) }

		return $vweb.html()
	}

	return $vweb.html()
}

fn main() {
	app := &App{}
	params := vweb.RunParams{
		port: 8080,
		nr_workers: 1,
    }

	vweb.run_at(app, params) or { panic(err) }
}
