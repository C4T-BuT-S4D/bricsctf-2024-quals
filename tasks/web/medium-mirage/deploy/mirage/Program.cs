using Mirage;

var server = new Server()
    .AddPrefix("http://*:8989/")
    .AddMiddleware(async (ctx, next) => {
        if (ctx.GetCookie("session") != null) {
            ctx.SetHeader(
                "Cross-Origin-Resource-Policy", "same-origin"
            );
            ctx.SetHeader(
                "Content-Security-Policy", (
                    "sandbox allow-scripts allow-same-origin; " +
                    "base-uri 'none'; " +
                    "default-src 'none'; " +
                    "form-action 'none'; " +
                    "frame-ancestors 'none'; " +
                    "script-src 'unsafe-inline'; "
                )
            );
        }

        await next(ctx);
    })
    .DefineGet("/admin", async ctx => {
        ctx.SetCookie("session", "admin");

        await ctx.Result("good luck");
    })
    .DefineGet("/xss", async ctx => {
        var xss = ctx.Request.QueryString.Get("xss");

        await ctx.Result(xss ?? "what??");
    })
    .DefineGet("/flag", async ctx => {
        var flag = Environment.GetEnvironmentVariable("FLAG");

        await ctx.Result(flag ?? "flag{example_flag}");
    });

await server.Run();
