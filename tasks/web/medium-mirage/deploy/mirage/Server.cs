using System.Net;

namespace Mirage {
    using Handler = Func<Context, Task>;
    using Middleware = Func<Context, Func<Context, Task>, Task>;

    public class Server {
        public enum HttpMethod {
            Get,
            Post,
        };

        private readonly HttpListener listener;
        private readonly List<Middleware> middlewares;
        private readonly Dictionary<string, Dictionary<HttpMethod, Handler>> router;

        public Server() {
            listener = new HttpListener();
            middlewares = new List<Middleware>();
            router = new Dictionary<string, Dictionary<HttpMethod, Handler>>();
        }

        public Server AddPrefix(string prefix) {
            listener.Prefixes.Add(prefix);

            return this;
        }

        public Server AddMiddleware(Middleware middleware) {
            middlewares.Add(middleware);

            return this;
        }

        public Server DefineRoute(string path, HttpMethod method, Handler handler) {
            if (!router.ContainsKey(path)) {
                router.Add(path, new Dictionary<HttpMethod, Handler>());
            }

            router[path][method] = handler;

            return this;
        }

        public Server DefineGet(string path, Handler handler) {
            return DefineRoute(path, HttpMethod.Get, handler);
        }

        public Server DefinePost(string path, Handler handler) {
            return DefineRoute(path, HttpMethod.Post, handler);
        }

        public async Task Run(CancellationToken token) {
            listener.Start();

            while (!token.IsCancellationRequested) {
                var context = new Context(
                    await listener.GetContextAsync()
                );

                try {
                    await RouteRequest(context);
                } catch (Exception e) {
                    await context.Result(e.ToString());
                }
            }

            listener.Stop();
        }

        public Task Run() {
            return Run(CancellationToken.None);
        }

        private async Task RouteRequest(Context context) {
            var path = context.Request.Url?.AbsolutePath ?? "/";
            var method = ParseHttpMethod(context.Request.HttpMethod);

            if (!router.ContainsKey(path)) {
                throw new Exception("route not found");
            }

            var route = router[path];

            if (!route.ContainsKey(method)) {
                throw new Exception("method is not suported");
            }

            var handler = route[method];

            await CallMiddlewareChain(context, middlewares);

            await handler.Invoke(context);
        }

        private Task CallMiddlewareChain(Context context, IEnumerable<Middleware> middlewares) {
            var middleware = middlewares.FirstOrDefault();

            if (middleware == null) {
                return Task.CompletedTask;
            }

            return middleware.Invoke(
                context,
                ctx => CallMiddlewareChain(ctx, middlewares.Skip(1))
            );
        }

        private HttpMethod ParseHttpMethod(string method) {
            switch (method.ToLower()) {
                case "get":
                    return HttpMethod.Get;

                case "post":
                    return HttpMethod.Post;

                default:
                    throw new Exception("unknown method");
            }
        }
    }
}
